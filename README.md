# gnl2go: Generic NetLink in Go

#### About:
This is go based lib to work with generic netlink socket's.
The lib was writen under heave influenc of FB's gnlpy
(i'd even say that i've complitly riped (translated from py to go) off their code base;
so all kudos goes to FB's team (@alexgartrell and co(took from comments:)) and all the blame to me)


in gnl2go.go you can find generic routines to work with gnetlink


in ipvs.go: lib to work with IPVS


in example/: few commands, which shows how to work with ipvs's lib

####TODOs:
bugfixes etc (i do know about incorrect ipv6struct to ipv6string conversion)
right now we do panic a lot. not sure that we should do it each time we bumped into error.
mb in production it would be more usefull to check err, and act according to it.
i dont use it (lib for ipvs) in production yet. not sure when i would. prob till that time i'd only fix
problem with ipv6 to string and any other minor bugs, which i'd bump into

