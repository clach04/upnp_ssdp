# upnp_ssdp

Python 2 Simple UPnP ssdp library for clients and servers. Uses stdlib.

Other libraries to consider:

  * https://github.com/Jnesselr/py-ssdp
  * http://brisa.garage.maemo.org/
      * http://brisa.garage.maemo.org/doc/html/upnp/ssdp.html
  * pydlnadms

## Info

upnp_ssdp.py can be imported to add discovery support to  an application,
either to find services or to advertise a new service.

Example search:

    upnp_ssdp.py

Example advertise service:

    upnp_ssdp.py server
