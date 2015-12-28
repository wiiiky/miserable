Miserable
===================

Miserable is my fork of Shadowsocks.

Shadowsocks is a fast tunnel proxy that was developed by clowwindy before.

For well-known reasons, clowwindy has to give up shadowsocks.

I have used shadowsocks instead of VPN for nearly 7 months to bypass the [Great Fire Wall](https://en.wikipedia.org/wiki/Great_Firewall). And I really like it.

Then I fork it and try to continue to develop it.

Refer to the original README written by clowwindy for more details about shadowsocks.

###Plan

I plan to re-implement most of Shadowsocks as it's simple naturally.

0.  I will change the name to Miserable completely sooner or later.

1.  I do not want to support Python2 anymore, I don't think it makes any sence since Python3 has been released for so many years and already been used and supported widely.

2.  I'm going to separate sslocal from sserver, which doesn't mean there will be two repositories, but the source code of them will be managed much more independently and clearly.

3. Documentations are really important for open source project, it helps others to understand the system principle and implementation details. So I'm going to document the protocol of Shadowsocks and some implementation details. Hope them helps.

4. I won't release next version of Shadowsocks until I think it has been re-implemented well. And it may be a long time before it.
