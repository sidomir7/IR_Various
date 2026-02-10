1. Run if not alredy included `Server.Import.Extras`
2. Label all computers 
3. Run `Windows.Forensics.PersistenceSniper` artifact on windows.
4. Analyze Persistence Sniper output.
5. Create IOCs and hunt on all machines.
6. Check all users on all machines.
7. Run `Windows.Forensics.Prefetch` and `Windows.Timeline.Prefetch`
   


Example how to parse OSPath
```
SELECT OSPath, pathspec(parse=OSPath, path_type="windows")[2] AS User, BTime, ClientId, Fqdn FROM source(artifact="Windows.Search.FileFinder")
```
