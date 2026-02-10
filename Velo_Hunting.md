1. label all computers 
2. Run `Windows.Forensics.PersistenceSniper` artifact on windows.
3. Analyze Persistence Sniper output.
4. Create IOCs and hunt on all machines.
5. Check all users on all machines.


Example how to parse OSPath
```
SELECT OSPath, pathspec(parse=OSPath, path_type="windows")[2] AS User, BTime, ClientId, Fqdn FROM source(artifact="Windows.Search.FileFinder")
```
