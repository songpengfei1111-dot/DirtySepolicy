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

In this implementation, the `AppZygote` uses the `SELinux.checkSELinuxAccess` API to analyze the system's global SELinux policies for "dirty" rules injected by common root and hooking solutions. 
Currently, the source code specifically checks if:
- `system_server` processes have `execmem` permission.
- `untrusted_app` processes can `call` the `magisk` binder (identifying Magisk).
- `untrusted_app` processes can `call` the `ksu` binder (identifying KernelSU).
- `untrusted_app` processes can `read` `lsposed_file` (identifying LSPosed).

Developers can easily extend this implementation by adding the specific SELinux rule characteristics of other future popular su solutions or root tools. 
Because the app zygote and zygote share code, SELinux permissions must be checked, otherwise, the process will crash, so this detection cannot be bypassed in userspace. 
The only way to circumvent this detection is by modifying the kernel itself.

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
