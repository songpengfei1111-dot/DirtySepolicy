# Dirty Sepolicy: Check Android SELinux access

This project discloses a method to detect the Android device sepolicy.
It can accurately identify all userspace su solutions, and it is impossible to bypass.

## Background

The LSPosed team originally discovered this method in August 2024.
At that time, we decided not to disclose it and chose not to implement this detection mechanism.

In May 2026, [FldBudin](https://github.com/FldBudin) independently discovered this method and made it public in [Duck Detector](https://github.com/eltavine/Duck-Detector-Refactoring/pull/22).
Given that the method is now publicly known, we have decided to publish our example implementation as well.

## How it works

The detection utilizes the **App Zygote** process. An App Zygote is an application-specific Zygote process that preloads resources and forks isolated services for the application.
To function correctly, the App Zygote must transition into the restricted context of the isolated service. Because of this requirement, it is indispensable for it to have the permission to [query and check SELinux access rules](https://android.googlesource.com/platform/system/sepolicy/+/master/private/app_zygote.te#:~:text=%23%20Check%20validity%20of%20SELinux,selinux_check_access(app_zygote)).
This inherent design makes it the perfect candidate to query SELinux without being restricted by normal untrusted app constraints.

In this implementation, the `AppZygote.java` uses its privileges to check the system's global SELinux policies for "dirty" rules injected by common root and hooking solutions.
- `security:compute_av`: Compute an access vector given a source, target and class, java api `SELinux.checkSELinuxAccess`, can detect the existence of specific allow rules.
- `security:check_context`: Determine whether the context is valid, no java api, you need to manually write `/sys/fs/selinux/context`, can detect the existence of specific type or domain.
- `process:setcurrent`: Set the current process context, no java api, you need to manually write `/proc/self/attr/current`, can also detect the existence of specific type or domain, because the kernel will check the validity of the requested context first and return `EINVAL` if the context is invalid. This is different from the case of no permission, which returns `EPERM` instead of `EINVAL` when the context is valid but the `process:dyntransition` is not allowed.

Developers can easily extend this implementation by adding the specific SELinux rule characteristics of other future popular su solutions or root tools.
Because the app zygote and zygote share code, SELinux permissions must be checked, otherwise, the process will crash, so this detection cannot be bypassed in userspace.
The only way to circumvent this detection is by modifying the kernel itself.

## app zygote crashed

App crashes or service bind timeout are most likely due to app zygote crashd, this should be seen as a signal that the check is being blocked by root.
It is important to note that selinux_check_access may [create SELinux netlink socket](https://cs.android.com/android/platform/superproject/+/android-11.0.0_r21:external/selinux/libselinux/src/checkAccess.c;l=22),
before Android 13, this socket is always created. This fd will be rejected when fork new app process, and crash app zygote.
App zygote can mark fds created during doPreload, but only after [Android 12](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r3:frameworks/base/core/java/com/android/internal/os/AppZygoteInit.java;l=94-96;drc=ff6ac69e69423107a626a00c3e01e9bf5eb2814c), 
developers should manually close this fd for old android versions.

## License

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
