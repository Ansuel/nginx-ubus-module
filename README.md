[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.me/AnsuelS) [![License](https://img.shields.io/github/license/Ansuel/nginx-ubus-module.svg?style=flat)](https://github.com/Ansuel/nginx-ubus-module/blob/master/LICENSE)

# Module ngx_http_read_request_body_module

The `ngx_http_ubus_module` module allows access ubus function directly from nginx without using cgi or additional application to connect to it
Ubus is used in openwrt to gain and set data to the system. Alle the comunication are done in json format.
This can be used to make gui that are based on only ubus request and calls.

This is based on `uhttpd-mod-ubus` module, some procedures are took from `uhttpd` module.

## Configuration example

```nginx
location /ubus {
        ubus_interpreter;
        ubus_socket_path /var/run/ubus.sock;
        ubus_script_timeout 600;
	      ubus_parallel_req 2;
      	ubus_cors off;
}
```

## Directives
<pre>
Syntax:  <b>ubus_interpreter</b>;
Default: —
Context: location
</pre>

Enable ubus_interpreter on the location set

<pre>
Syntax:  <b>ubus_socket_path</b>;
Default: —
Context: location
</pre>

The path to the socket the module will connect to. Without this the module will report a json error with Internal Error

<pre>
Syntax:  <b>ubus_script_timeout</b>;
Default: 60
Context: location
</pre>

Ubus connection will be terminated after the timeout is exceeded

<pre>
Syntax:  <b>ubus_parallel_req</b>;
Default: 1
Context: location
</pre>

With batched request, the module will create n thread to handle request quickly. 
_**Note**_: Ubus doesn't support parallel request so the speedup is not too noticable

<pre>
Syntax:  <b>ubus_cors</b>;
Default: 0
Context: location
</pre>

Adds cors header security options to every response header

<pre>
Syntax:  <b>ubus_noauth</b>;
Default: 0
Context: location
</pre>

Only for test purpose. This will denied every request.

