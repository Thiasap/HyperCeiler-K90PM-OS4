/* SPDX-License-Identifier: AGPL-3.0-or-later */
package com.sevtinge.hyperceiler.libhook.rules.home.recent;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Binder;
import android.os.Bundle;
import android.os.Parcel;
import android.os.PowerManager;
import android.os.SystemClock;
import android.app.KeyguardManager;
import com.sevtinge.hyperceiler.common.log.ModuleLog;
import com.sevtinge.hyperceiler.common.utils.PrefsBridge;
import com.sevtinge.hyperceiler.libhook.rules.home.gesture.HomeQuickSwitchOS4;
import com.sevtinge.hyperceiler.libhook.utils.api.ContextUtils;

import java.util.concurrent.atomic.AtomicLong;

/** HCV1 scroll compatibility and HCV2 independent close channel, both use one provider snapshot. */
public final class HomeRecentsHapticEndpointOS4 {
    public static final int TRANSACTION=HomeRecentsHapticProtocol.TRANSACTION,ACK=HomeRecentsHapticProtocol.ACK;
    public static final int TRANSACTION_V2=HomeRecentsHapticProtocol.TRANSACTION_V2;
    private static final Uri PREFS=Uri.parse("content://com.sevtinge.hyperceiler.provider.sharedprefs/home_recents_haptic");

    /**
     * The launcher probes this endpoint once per second for as long as its layout lease lives, so
     * the answer must not cost a provider read every time. system_server is a permanent client of
     * the module app, and every read wakes a process HyperOS has just frozen - the frozen read is
     * then counted as an unstable provider and kills the app, which restarts it, which makes the
     * next read wake it again. Measured on the K90 Pro Max, a one-per-second read held that cycle
     * at one cold start per minute, and a thirty-second read merely moved the pacemaker: the
     * process restarted every thirty seconds instead.
     *
     * <p>So the read is event driven. The remote-preferences listener below is the only steady
     * state trigger; this TTL applies solely when LSPosed's push never arrived, where a bounded
     * staleness is still better than a frozen configuration for the life of system_server.
     */
    private static final long PROVIDER_TTL_MS=30_000L;

    /**
     * Backoff for consecutive failed reads.
     *
     * <p>A failure is usually "the module app was frozen when we asked", so retrying promptly is
     * what turns one failed read into a kill storm. The native side re-probes every five seconds
     * after an unavailable answer, and the cached failure answers it for free.
     */
    private static final long[] FAILURE_BACKOFF_MS={5_000L,15_000L,60_000L,300_000L};

    /** Keys {@link com.sevtinge.hyperceiler.libhook.provider.HomeRecentsHapticPrefs} reads. */
    private static final String[] KEYS={
        "prefs_key_home_recent_card_haptic","prefs_key_home_recent_card_close_haptic",
        "prefs_key_home_recent_card_haptic_type","prefs_key_home_recent_card_haptic_strength",
        "prefs_key_framework_api_allow_hook"};

    private static final AtomicLong NOTIFICATIONS=new AtomicLong();
    private static final Object CACHE_LOCK=new Object();
    private static volatile SharedPreferences remotePrefs;
    private static volatile SharedPreferences.OnSharedPreferenceChangeListener prefsListener;
    private static Snapshot cached;
    private static int consecutiveFailures;
    private static int reported;
    private HomeRecentsHapticEndpointOS4() {}

    /** Decoded provider answer; {@code available == 0} means "no usable snapshot". */
    private record Snapshot(int available,int enabled,int close,int type,int strength,int version,long atMs) {
        static Snapshot unavailable(int version,long atMs){return new Snapshot(0,0,0,0,50,version,atMs);}
    }

    public static void receive(Parcel data,Parcel reply,int flags) {receive(data,reply,flags,false);}
    public static void receive(Parcel data,Parcel reply,int flags,boolean extended) {
        int available=0,enabled=0,close=0,type=0,strength=50,result=0;
        try {
            data.enforceInterface("android.view.IWindowManager");
            int operation=data.readInt();long timestamp=data.readLong();int count=data.readInt();
            var context=ContextUtils.getContextNoError(ContextUtils.FlAG_ONLY_ANDROID);
            if(!(extended?HomeRecentsHapticProtocol.validExtendedRequest(operation,timestamp,count,flags,data.dataAvail(),SystemClock.uptimeMillis())
                :HomeRecentsHapticProtocol.validRequest(operation,timestamp,count,flags,data.dataAvail(),SystemClock.uptimeMillis()))
                ||context==null||!HomeQuickSwitchOS4.isLauncher(context,Binder.getCallingUid(),Binder.getCallingPid())){
                writeReply(reply,extended,0,0,0,0,50,0);return;
            }
            final Snapshot profile=snapshot(context);
            if(profile.available()==1){
                enabled=profile.enabled();close=profile.close();type=profile.type();strength=profile.strength();
                available=1;
                if(operation==0)result=1;
                else if((operation==2?close:enabled)==1&&SystemClock.uptimeMillis()-timestamp<=200
                    &&context.getSystemService(PowerManager.class).isInteractive()
                    &&!context.getSystemService(KeyguardManager.class).isKeyguardLocked())
                    result=HomeRecentsHapticOS4.perform(context,type,strength,count)?1:0;
            }
        } catch(Exception failure){
            if(reported++<3)ModuleLog.w("HyperCeiler.HomeLayout","recents haptic endpoint unavailable",failure);
        }
        writeReply(reply,extended,available,enabled,close,type,strength,result);
    }

    /**
     * The cached snapshot, refreshed on a settings change or after the bounded fallback.
     *
     * <p>Single-flight by construction: the lock is held across the read, so the one-per-second
     * probes of a leaping launcher collapse into one provider call instead of one call each.
     */
    private static Snapshot snapshot(Context context) {
        ensurePrefsListener();
        synchronized(CACHE_LOCK){
            final int version=(int)NOTIFICATIONS.get();
            final long now=SystemClock.uptimeMillis();
            final Snapshot current=cached;
            if(current!=null&&current.version()==version){
                final long age=now-current.atMs();
                if(current.available()==1){
                    // Push, not poll. With the listener in place the version is the only trigger.
                    if(remotePrefs!=null||age<PROVIDER_TTL_MS)return current;
                } else if(age<failureBackoff()){
                    return current;
                }
            }
            final Snapshot fresh=readProvider(context,version,now);
            consecutiveFailures=fresh.available()==1?0:consecutiveFailures+1;
            cached=fresh;
            return fresh;
        }
    }

    private static long failureBackoff() {
        return FAILURE_BACKOFF_MS[Math.min(Math.max(consecutiveFailures,0),FAILURE_BACKOFF_MS.length-1)];
    }

    /** One provider read. Never throws: a broken channel must not break the WMS binder thread. */
    private static Snapshot readProvider(Context context,int version,long atMs) {
        final long token=Binder.clearCallingIdentity();
        try(var cursor=context.getContentResolver().query(PREFS,null,null,null,null)){
            if(cursor==null||cursor.getColumnCount()!=4||!cursor.moveToFirst()||cursor.getInt(0)!=1)
                return Snapshot.unavailable(version,atMs);
            final int enabled=cursor.getInt(1),type=cursor.getInt(2),strength=cursor.getInt(3);
            var extras=cursor.getExtras();
            final int close=extras!=null&&extras.getInt("close_version",0)==1?extras.getInt("close_enabled",0):0;
            if(enabled<0||enabled>1||close<0||close>1||type<0||type>3||strength<10||strength>100)
                return Snapshot.unavailable(version,atMs);
            return new Snapshot(1,enabled,close,type,strength,version,atMs);
        } catch(RuntimeException|Error failure){
            if(reported++<3)ModuleLog.w("HyperCeiler.HomeLayout","recents haptic snapshot unavailable",failure);
            return Snapshot.unavailable(version,atMs);
        } finally {Binder.restoreCallingIdentity(token);}
    }

    /**
     * Subscribe to the pushed preference snapshot so an edit reaches the probe immediately.
     *
     * <p>Registered once and never released: the endpoint lives as long as system_server. Only the
     * keys this snapshot is built from count, so an unrelated edit does not force a provider read.
     */
    private static void ensurePrefsListener() {
        if(remotePrefs!=null)return;
        synchronized(CACHE_LOCK){
            if(remotePrefs!=null)return;
            try{
                final SharedPreferences prefs=PrefsBridge.getSharedPreferences();
                if(prefs==null)return;
                final SharedPreferences.OnSharedPreferenceChangeListener candidate=(changed,key)->{
                    if(key==null||isHapticKey(key))NOTIFICATIONS.incrementAndGet();
                };
                prefs.registerOnSharedPreferenceChangeListener(candidate);
                prefsListener=candidate;
                remotePrefs=prefs;
            } catch(RuntimeException|Error unavailable){
                // Losing the push only costs the TTL: the cached answer stays bounded and valid.
            }
        }
    }

    private static boolean isHapticKey(String key) {
        for(String candidate:KEYS)if(candidate.equals(key))return true;
        return false;
    }

    private static void writeReply(Parcel reply,boolean extended,int available,int enabled,int close,int type,int strength,int result) {
        if(available==0){enabled=close=type=result=0;strength=50;}
        reply.writeInt(extended?HomeRecentsHapticProtocol.ACK_V2:ACK);reply.writeInt(available);reply.writeInt(enabled);
        if(extended)reply.writeInt(close);
        reply.writeInt(type);reply.writeInt(strength);reply.writeInt(result);
    }
}
