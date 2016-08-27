# Virus Sprecher

* Get result of file scan by virustotal through its API.
* Written in Python(2.7.11).
* Program uses "aplay", it works on Linux.

## How to use

At first, visit [VirusTotal(https://www.virustotal.com)](https://www.virustotal.com) and join to the community. Then, you can get your API key(Set it into "config.py").

exec:

```
$ python sprecher.py FILE_PATH
```

After few minutes, program will receive result report from VirusTotal, and voice(wav) will be generate and speak on your computer(Note: wav file will be saved to your working directory).

## Attention

* I asssume no responsibility for any loss, damages and troubles caused by program execution. **Take full responsibility for your actions**.

* FILE\_PATH will be **shown on VirusTotal** result page(attention no upload private/secret/important/personal file so as not to leak your informations).


I checked this program on Raspberry Pi(Model B), it works.

about this program -> [my blog](http://wassan128.github.io/blog/2016/08/24/)
