# 제28장 모바일 해킹 심층: 안드로이드 네이티브 SO 분석 & Frida SSL 언피닝 심층 분석 (Deep-dive)

> **난이도**: ★★★★★ | **실습 연계**: [Lab 07 (MobileLab)](file:///mnt/d/바이브해킹%20자료/vibe-hacking/labs/07_mobile_lab/README.md) & [Lab 19 (DroidShield)](file:///mnt/d/바이브해킹%20자료/vibe-hacking/labs/19_android_frida_lab/README.md) | **워게임 트랙**: `droidpwn` / `mobile`

---

## 1. 개요 및 안드로이드 JNI 아키텍처

최신 안드로이드 금융, 게임, 엔터프라이즈 앱은 역공학 및 동적 조작을 방어하기 위해 핵심 비즈니스 로직, 암호화 키 파생(KDF), 토큰 서명, 무결성 검증, 네트워크 보안 검사를 **JNI(Java Native Interface) 네이티브 라이브러리(`*.so`)** 내부로 은닉합니다.

```mermaid
flowchart TD
    subgraph Java/Kotlin Layer
        App["App Logic (UI / Service)"]
        OkHttp["OkHttp3 / TrustManager"]
        JNI_Bridge["Native Method Declaration: native void verify()"]
    end

    subgraph ART Runtime
        DVM["ART Virtual Machine"]
        JNIEnv["JNIEnv Pointer / Function Table"]
    end

    subgraph Native C/C++ Layer (.so)
        OnLoad["JNI_OnLoad(JavaVM*, void*)"]
        RegNative["RegisterNatives() Dynamic Mapping"]
        CryptoCore["BoringSSL / OpenSSL SSL_CTX_set_custom_verify()"]
        AntiDebug["Anti-Frida: /proc/self/maps Scan & ptrace()"]
    end

    App --> JNI_Bridge
    JNI_Bridge --> DVM
    DVM --> JNIEnv
    JNIEnv --> OnLoad
    OnLoad --> RegNative
    RegNative --> CryptoCore & AntiDebug
```

### 1.1 JNI 함수 바인딩 메커니즘
1. **정적 바인딩 (Static Export)**:
   - 심볼 테이블에 `Java_패키지명_클래스명_메서드명` 형태로 노출됩니다.
   - 예: `Java_com_vibe_bank_SecurityCore_verifyToken(JNIEnv *env, jobject thiz, jstring token)`
   - Ghidra/IDA Pro에서 함수명이 그대로 식별되므로 분석이 상대적으로 용이합니다.
2. **동적 바인딩 (Dynamic Registration via `RegisterNatives`)**:
   - 심볼 테이블에 노출되지 않고, 라이브러리가 로드될 때 `JNI_OnLoad()` 함수 내에서 `env->RegisterNatives()`를 호출하여 Java 메서드 시그니처와 네이티브 함수 포인터를 런타임에 매핑합니다.
   - 분석 방해 기법으로 널리 사용되며, 네이티브 함수 주소를 찾기 위해 `JNINativeMethod` 배열 구조체를 분석해야 합니다.

```c
// JNI_OnLoad 내의 RegisterNatives 패턴 예시
typedef struct {
    const char* name;      // Java 메서드명
    const char* signature; // Java 파라미터/반환값 타입 시그니처
    void*       fnPtr;     // 실제 네이티브 C 함수 포인터
} JNINativeMethod;

static JNINativeMethod methods[] = {
    {"validateDeviceIntegrity", "(Ljava/lang/String;)Z", (void*)&native_check_device},
    {"decryptPayload", "([B)[B", (void*)&native_aes_decrypt}
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    JNIEnv* env;
    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    jclass cls = (*env)->FindClass(env, "com/vibe/sec/NativeCore");
    (*env)->RegisterNatives(env, cls, methods, sizeof(methods)/sizeof(methods[0]));
    return JNI_VERSION_1_6;
}
```

---

## 2. Ghidra를 활용한 RegisterNatives 동적 바인딩 해체

Ghidra로 `libnative-crypto.so`를 분석할 때, `JNI_OnLoad`의 `RegisterNatives` 호출 파라미터를 추적하여 네이티브 함수의 실제 가상 주소(VMA)를 식별합니다.

### 2.1 JNINativeMethod 역공학 절차
1. Ghidra Symbol Tree에서 `JNI_OnLoad`를 검색하고 Decompile 창을 확인합니다.
2. `RegisterNatives` 호출부를 찾습니다:
   `(*(*env)->RegisterNatives)(env, targetClass, methodsPtr, count);`
3. 3번째 인자인 `methodsPtr`가 가리키는 메모리 주소(일반적으로 `.data` 또는 `.rodata` 섹션)로 이동합니다.
4. 해당 메모리 영역의 데이터 타입을 `JNINativeMethod[n]` 배열로 정의(Type Define)하면, 감춰진 네이티브 C 함수의 실제 오프셋과 디컴파일 결과를 확보할 수 있습니다.

---

## 3. 다계층 SSL Pinning 해부 & 통합 우회 (Universal Unpinning)

최신 모바일 앱은 중간자 공격(MITM)을 원천 차단하기 위해 단일 계층이 아닌 다중 계층(Java 계층 + 네이티브 OpenSSL/BoringSSL 계층 + Flutter 렌더러)에 SSL Pinning을 적용합니다.

### 3.1 주요 SSL Pinning 계층 구조
1. **Java/Android Framework 계층**:
   - `TrustManagerImpl`: `checkTrustedRecursive()`
   - `CertificatePinner`: OkHttp3 `check(String hostname, List<Certificate> peerCertificates)`
   - `NetworkSecurityConfig`: `res/xml/network_security_config.xml` 내 `<pin-set>`
2. **Native C/BoringSSL 계층**:
   - OpenSSL/BoringSSL: `SSL_CTX_set_custom_verify`, `SSL_set_custom_verify`
   - Conscrypt 라이브러리: `SSL_do_handshake`
3. **Flutter / Dart 계층**:
   - Flutter는 시스템 CA 저장소를 무시하고 엔진 바이너리(`libflutter.so`) 내부의 내장 BoringSSL 루틴을 사용합니다.
   - `session_verify_cert_chain` 검증 함수를 직접 패치해야 합니다.

### 3.2 엔터프라이즈 통합 Frida SSL Unpinning 스크립트

다음 스크립트는 Java 프레임워크(OkHttp3, TrustManager, Conscrypt, WebView)와 네이티브 BoringSSL 계층을 동시에 무력화합니다:

```javascript
/*
 * Universal Multi-Tier SSL Pinning Bypass (Java + Native BoringSSL)
 */
Java.perform(function () {
    console.log("[*] Initializing Universal Multi-Tier SSL Unpinning...");

    // 1. TrustManagerImpl 무력화 (Android 7.0+)
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log("[+] [TrustManagerImpl] Bypassing verifyChain for host: " + host);
            return untrustedChain; // 검증 없이 체인 반환
        };
    } catch (err) {
        console.log("[-] TrustManagerImpl not found: " + err);
    }

    // 2. OkHttp3 CertificatePinner 무력화
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (hostname, peerCertificates) {
            console.log("[+] [OkHttp3] Bypassing CertificatePinner.check(String, List) for: " + hostname);
            return; // 예외 없이 정상 리턴
        };
        CertificatePinner.check$okhttp.overload('java.lang.String', 'kotlin.jvm.functions.Function0').implementation = function (hostname, fn) {
            console.log("[+] [OkHttp3] Bypassing CertificatePinner.check$okhttp for: " + hostname);
            return;
        };
    } catch (err) {
        console.log("[-] OkHttp3 CertificatePinner not found: " + err);
    }

    // 3. NetworkSecurityConfig (Android 7.0+) 우회
    try {
        var NetworkSecurityTrustManager = Java.use('android.security.net.config.NetworkSecurityTrustManager');
        NetworkSecurityTrustManager.checkPins.implementation = function (pins) {
            console.log("[+] [NetworkSecurityConfig] Bypassing checkPins()");
            return;
        };
    } catch (err) {
        console.log("[-] NetworkSecurityTrustManager not found: " + err);
    }
});

// 4. Native Layer (libflutter.so / libssl.so) 패칭
function hookNativeSSL() {
    var targets = ["libflutter.so", "libssl.so", "libcrypto.so"];
    targets.forEach(function (libName) {
        var module = Process.findModuleByName(libName);
        if (module) {
            console.log("[+] Found native SSL module: " + libName + " at " + module.base);
            // SSL_set_custom_verify 심볼 후킹
            var sslSetCustomVerify = Process.findExportByName(libName, "SSL_set_custom_verify");
            if (sslSetCustomVerify) {
                Interceptor.attach(sslSetCustomVerify, {
                    onEnter: function (args) {
                        console.log("[+] Hooked SSL_set_custom_verify in " + libName);
                        // args[1]은 verify_mode (SSL_VERIFY_NONE = 0으로 강제 변환)
                        args[1] = ptr(0);
                    }
                });
            }
        }
    });
}
setImmediate(hookNativeSSL);
```

---

## 4. 안티-프리다(Anti-Frida) 탐지 기법과 우회 전략

금융 및 보안 앱은 동적 계측을 차단하기 위해 런타임에 다수의 프리다 탐지 센서를 구동합니다.

### 4.1 안티-프리다 5대 탐지 메커니즘
| 탐지 기법 | 탐지 원리 | 주요 탐지 지표 |
| :--- | :--- | :--- |
| **기본 포트 바인딩 검사** | `127.0.0.1:27042` TCP 연결 시도 | 연결 성공 시 frida-server 실행 중으로 판단 |
| **메모리 맵 검사 (`maps`)** | `/proc/self/maps` 파일 읽기 | `frida-agent.so`, `gum-js-loop`, `linjector` 문자열 검색 |
| **디버깅 상태 검사 (`status`)** | `/proc/self/status` 내 `TracerPid` 필드 | `TracerPid != 0`인 경우 ptrace 부착 탐지 |
| **스레드 이름 검사** | `/proc/self/task/{id}/comm` 열거 | `gmain`, `gdbus`, `gum-js-loop` 이름의 워커 스레드 탐지 |
| **인라인 후킹 무결성 검사** | `libc.so` 내 주요 API의 첫 4바이트 검사 | ARM64 브랜치 명령어 (`LDR PC, [PC, #0]` 또는 `BR X16`) 여부 검사 |

### 4.2 안티-프리다 무력화 CModule 및 Frida 후킹

```javascript
/*
 * Anti-Frida Maps & File Scanner Bypass
 */
var openPtr = Module.findExportByName("libc.so", "open");
var openHook = Interceptor.attach(openPtr, {
    onEnter: function (args) {
        var path = Memory.readUtf8String(args[0]);
        this.isProcScan = false;
        if (path && (path.indexOf("/proc/self/maps") !== -1 || path.indexOf("/proc/self/status") !== -1)) {
            this.isProcScan = true;
            // 허위 안전 파일로 리디렉션
            var fakePath = Memory.allocUtf8String("/data/local/tmp/fake_maps");
            args[0] = fakePath;
            console.log("[+] Redirected proc scan: " + path + " -> /data/local/tmp/fake_maps");
        }
    }
});

// ptrace 탐지 방지
var ptracePtr = Module.findExportByName("libc.so", "ptrace");
if (ptracePtr) {
    Interceptor.attach(ptracePtr, {
        onEnter: function (args) {
            var req = args[0].toInt32();
            if (req === 0 /* PTRACE_TRACEME */) {
                console.log("[+] Neutralized ptrace(PTRACE_TRACEME)");
                this.shouldFake = true;
            }
        },
        onLeave: function (retval) {
            if (this.shouldFake) {
                retval.replace(0); // 항상 성공(0) 반환
            }
        }
    });
}
```

---

## 5. 방어 아키텍처 및 하드닝 권고안

1. **Hardware-backed KeyStore & Attestation**:
   - 키를 애플리케이션 메모리에 직접 올리지 않고, Android StrongBox / TEE(Trusted Execution Environment) 내부에서 비대칭 키쌍을 생성하고 서명 연산을 TEE 내부로 위임합니다.
2. **Play Integrity API (구 SafetyNet)**:
   - 클라이언트 로컬 체크에 의존하지 않고, Google Play 서버가 발행한 암호화된 기기 무결성 토큰(`appLicensingVerdict`, `deviceIntegrity`)을 백엔드 서버에서 직접 Google API로 검증합니다.
3. **네이티브 제어 흐름 평탄화 (OLLVM/Hikari)**:
   - 핵심 C/C++ 소스코드 빌드 시 Control Flow Flattening, Bogus Control Flow, Instruction Substitution 컴파일러 패스를 적용하여 Ghidra 디컴파일 난이도를 극대화합니다.
