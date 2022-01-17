#!/bin/bash -e

# Auxiliary files
mkdir lib/
mkdir lib/godoc
godoc -url http://localhost:6060/lib/godoc/godocs.js > ./lib/godoc/godocs.js
godoc -url http://localhost:6060/lib/godoc/jquery.js > ./lib/godoc/jquery.js
godoc -url http://localhost:6060/lib/godoc/style.css > ./lib/godoc/style.css

# Generate the doc (the first line generated is garbage, removed with "tail")
export pkg="httpsign"
godoc -url http://localhost:6060/pkg/$pkg | tail -n +2 > $pkg.html

echo "Generated $pkg.html"