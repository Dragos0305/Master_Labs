#!/bin/bash


curl http://141.85.224.104:40000/advanced/F >> FLAG
curl http://141.85.224.104:40000/xxx/L >> FLAG
curl http://141.85.224.104:40000/reusablecontent/A >> FLAG
curl http://141.85.224.104:40000/secrets/G >> FLAG

cat FLAG | paste -s | sed 's/\t//g'
