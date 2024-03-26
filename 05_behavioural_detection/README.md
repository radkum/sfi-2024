# Bedet-rs (BEhavaiour DETection)

###Directory hierarchy
**bedet-km** - minifilter project 

**bedet-um** - user mode program to configure minifilter

**bedet** - shared info between driver and client, like ioctl codes

### How to use
#### Installing (with admin rights):
Click right mouse button on Bedet.inf and choose install or type
> RUNDLL32.EXE SETUPAPI.DLL,InstallHinfSection DefaultInstall 132 C:\VsExclude\kernel\bedet\bedet.inf

#### Start: 
> fltmc load bedet

#### Setup minifilter:
Todo
> bedet-client.exe 


#### Stop:
> fltmc unload minifilter