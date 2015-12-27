Shadowsocks
===================

Shadowsocks is a fast tunnel proxy that was developed by clowwindy at first.

For well-known reasons, clowwindy has to give up shadowsocks.

I have used shadowsocks instead of VPN for nearly 7 months to bypass the [Great Fire Wall](https://en.wikipedia.org/wiki/Great_Firewall). And I really like it.

Then I fork it and try to continue to develop it.

Refer to the original README written by clowwindy for more details about shadowsocks.

###Plan

To be honest, the source code of Shadowsocks is not as good as I think (since it's a so long time developed open source project).
So I plan to re-implement most of it as it's simple naturally.

1.  I do not want to support Python2 anymore, I don't think it makes any sence since Python3 has been released for so many years and already been used and supported widely.

2.  I'm going to separate sslocal from sserver, which doesn't mean there will be two repositories, but the source code of them will be managed much more independently and clearly.

3. Documentations are really important for open source project, it helps others to understand the system principle and implementation details. So I'm going to document the protocol of Shadowsocks some the implementation details. Hope them helps.

4. I won't release next version of Shadowsocks until I think it has been re-implemented well. And it may be a long time before it.

5. Perhaps I should change the name of Shadowsocks to avoid troubles. Any idea?
