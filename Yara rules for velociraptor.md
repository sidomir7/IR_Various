Yara rules for finding interesting files etc ... 
Rule for detecting AWS Access key on system. Can be used with `Linux.Search.FileFinder` and `Windows.Search.FileFinder` velociraptor artifacts. 

```
rule Possible_AWS_AccessKeyId
{
  meta:
    description = "Detects possible AWS Access Key ID pattern (AKIA + 16 alnum)"
    date = "2026-02-10"

  strings:
    $aws_key = /AKIA[0-9A-Z]{16}/

  condition:
    $aws_key
}
```
