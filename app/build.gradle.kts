// file:noinspection DependencyNotationArgument
import com.android.build.api.dsl.ApplicationBuildType
import com.android.build.gradle.tasks.PackageAndroidArtifact
import java.text.SimpleDateFormat
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import java.util.Date
import java.util.Properties
import java.util.TimeZone

plugins {
    alias(libs.plugins.android.application)
}

val apkId = "HyperCeiler"
val gitHash: String by lazy { runGitCommand("rev-parse", "--short", "HEAD") ?: "unknown" }
val gitHashLong: String by lazy { runGitCommand("rev-parse", "HEAD") ?: "unknown" }
val gitCommitCount: Int by lazy { runGitCommand("rev-list", "--count", "HEAD")?.toIntOrNull() ?: 0 }
val gitBranch: String by lazy {
    val url = runGitCommand("remote", "get-url", "origin") ?: "unknown"
    val branch = runGitCommand("branch", "--show-current") ?: "unknown"
    """github\.com[:/](.+?)(\.git)?$""".toRegex().find(url)?.groupValues?.get(1).orEmpty() + "/" + branch
}
val gitVersionCode: Int by lazy { 5 + gitCommitCount }

fun runGitCommand(vararg args: String): String? = runCatching {
    ProcessBuilder(listOf("git") + args)
        .redirectErrorStream(true)
        .start()
        .let { process ->
            val output = process.inputStream.bufferedReader().readText().trim()
            if (process.waitFor() == 0 && output.isNotBlank()) output else null
        }
}.getOrNull()

fun loadPropertiesFromFile(fileName: String): Properties? =
    rootProject.file(fileName).takeIf { it.isFile }?.let { file ->
        Properties().apply { file.inputStream().use { load(it) } }
    }

// 提到顶层：afterEvaluate 里也要用（决定产物名是否带 -debug），而 android {} 里声明的东西出不了那个 lambda。
val signingProperties: Properties? by lazy { loadPropertiesFromFile("signing.properties") }

fun signingValue(propertyName: String, environmentName: String): String? =
    signingProperties?.getProperty(propertyName)?.takeIf { it.isNotBlank() }
        ?: providers.environmentVariable(environmentName).orNull?.takeIf { it.isNotBlank() }

// 四个值全齐才算配置了真签名；任何一项缺失，AGP 都会退回 "debug" 签名配置（CN=Android Debug）。
val hasCustomSigning: Boolean by lazy {
    listOf(
        "storeFile" to "STORE_FILE",
        "storePassword" to "STORE_PASSWORD",
        "keyAlias" to "KEY_ALIAS",
        "keyPassword" to "KEY_PASSWORD",
    ).all { (property, environment) -> signingValue(property, environment) != null }
}

android {
    namespace = "com.sevtinge.hyperceiler"
    compileSdk = 37
    compileSdkMinor = 0
    buildToolsVersion = "37.0.0"

    defaultConfig {
        applicationId = namespace
        minSdk = 35
        targetSdk = 37
        versionCode = gitVersionCode
        versionName = "2.11.170"

        val buildTime = SimpleDateFormat("yyyy-MM-dd HH:mm:ss").apply {
            timeZone = TimeZone.getTimeZone("Asia/Shanghai")
        }.format(Date())

        val buildConfigData = mapOf(
            "BUILD_TIME" to buildTime,
            "BUILD_OS_NAME" to System.getProperty("os.name"),
            "BUILD_USER_NAME" to System.getProperty("user.name"),
            "BUILD_JAVA_VERSION" to System.getProperty("java.version"),
            "GIT_BRANCH" to gitBranch
        )

        for ((key, value) in buildConfigData) {
            buildConfigField("String", key, "\"$value\"")
        }

        ndk {
            // noinspection ChromeOsAbiSupport
            abiFilters += "arm64-v8a"
        }

        externalNativeBuild {
            cmake {
                cppFlags += listOf("-std=c++20", "-fvisibility=hidden")
            }
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
        }
    }

    buildFeatures {
        aidl = true
        buildConfig = true
    }

    androidResources {
        additionalParameters += listOf("--allow-reserved-package-id", "--package-id", "0x36")
    }

    packaging {
        resources {
            merges += listOf("META-INF/xposed/*")
            excludes += listOf("**")
        }
        jniLibs {
            useLegacyPackaging = false
        }
        dex {
            useLegacyPackaging = true
        }
    }

    val buildTimeSuffix: String by lazy {
        SimpleDateFormat("MMddHHmm").apply {
            timeZone = TimeZone.getTimeZone("Asia/Shanghai")
        }.format(Date())
    }
    val dateSuffix: String by lazy {
        DateTimeFormatter.ofPattern("yyyyMMdd").format(LocalDateTime.now())
    }

    val customSigningConfig = if (hasCustomSigning) {
        signingConfigs.create("hasProperties") {
            storeFile = file(signingValue("storeFile", "STORE_FILE")!!)
            storePassword = signingValue("storePassword", "STORE_PASSWORD")
            keyAlias = signingValue("keyAlias", "KEY_ALIAS")
            keyPassword = signingValue("keyPassword", "KEY_PASSWORD")
            enableV1Signing = true
            enableV2Signing = true
            enableV3Signing = true
            enableV4Signing = true
        }
    } else {
        null
    }

    buildTypes {
        val configSigning: ApplicationBuildType.() -> Unit = {
            signingConfig = customSigningConfig ?: signingConfigs.getByName("debug")
        }

        val applyBase: ApplicationBuildType.() -> Unit = {
            optimization.enable = true
            buildConfigField("String", "GIT_CODE", "\"$gitVersionCode\"")
        }

        release {
            applyBase()
            configSigning()
            buildConfigField("String", "GIT_HASH", "\"$gitHash\"")
            versionNameSuffix = "-$dateSuffix"
        }

        create("beta") {
            applyBase()
            configSigning()
            buildConfigField("String", "GIT_HASH", "\"$gitHashLong\"")
            versionNameSuffix = "-$dateSuffix"
        }

        create("canary") {
            applyBase()
            configSigning()
            buildConfigField("String", "GIT_HASH", "\"$gitHashLong\"")
            versionNameSuffix = "-${gitHash}-r${gitVersionCode}"
        }

        debug {
            configSigning()
            isMinifyEnabled = false
            buildConfigField("String", "GIT_HASH", "\"$gitHashLong\"")
            buildConfigField("String", "GIT_CODE", "\"$gitVersionCode\"")
            versionNameSuffix = "-${buildTimeSuffix}-r${gitVersionCode}"
        }
    }

    lint {
        toolchain {
            languageVersion = JavaLanguageVersion.of(25)
        }
    }
}

afterEvaluate {
    base {
        val buildTypeName = gradle.startParameter.taskNames
            .firstOrNull { it.contains("assemble", ignoreCase = true) }
            ?.substringAfterLast(":")
            ?.replace("assemble", "", ignoreCase = true)
            ?.lowercase() ?: "debug"
        val suffix = android.buildTypes.findByName(buildTypeName)?.versionNameSuffix ?: ""
        // 没配置真签名时会退回 debug 密钥签名，在产物文件名上标注 -debug 以便一眼区分
        val debugKeyTag = if (!hasCustomSigning && buildTypeName != "debug") {
            logger.warn("signing.properties 不存在或四项签名值不全，$buildTypeName 产物将使用 debug 密钥签名，文件名带 -debug 标记")
            "-debug"
        } else {
            ""
        }
        archivesName.set("$apkId-${android.defaultConfig.versionName}$suffix$debugKeyTag")
    }
}

// https://stackoverflow.com/a/77745844
tasks.withType<PackageAndroidArtifact> {
    doFirst { appMetadata.asFile.orNull?.writeText("") }
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(25)
    }
}

kotlin.jvmToolchain(25)

dependencies {
    implementation(libs.viewpager2)
    implementation(libs.expansion)
    implementation(projects.library.core)
    implementation(projects.library.common)

    api (libs.room.runtime)
    // FTS 支持
    api (libs.room.ktx)
    annotationProcessor (libs.room.compiler)
}

/**
 * Host-side native tests for the NativeHookRuntime (app/src/main/cpp/nativehook/)
 * and the desktop Dart hook's host-testable layers.
 *
 * These run on the build machine, not on Android: they need no device and no
 * Android SDK. On Linux they also build the ARM64 assembly harness test; on
 * macOS that single test is skipped by the script (eventfd / GNU as).
 *
 * Usage: ./gradlew :app:hostNativeTests
 * Optional: ./gradlew :app:hostNativeTests -PlibappSo=/path/to/libapp.so
 */
tasks.register<Exec>("hostNativeTests") {
    group = "verification"
    description = "Compiles and runs the host native tests (no device required)"
    workingDir = rootProject.projectDir
    val script = rootProject.file("tests/run_host_native_tests.sh")
    commandLine(buildList {
        add("bash")
        add(script.absolutePath)
        (project.findProperty("libappSo") as String?)?.let { add(it) }
    })
}
