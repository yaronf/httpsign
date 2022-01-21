#!/bin/bash -e

# Auxiliary files
mkdir lib/
mkdir lib/godoc
# godoc adds a header line to every file
godoc -url http://localhost:6060/lib/godoc/godocs.js | tail -n +2 > ./lib/godoc/godocs.js
godoc -url http://localhost:6060/lib/godoc/jquery.js | tail -n +2 > ./lib/godoc/jquery.js
godoc -url http://localhost:6060/lib/godoc/style.css | tail -n +2 > ./lib/godoc/style.css

# Generate the doc (the first line generated is garbage, removed with "tail")
export suffix=httpsign
export pkg="github.com/yaronf/$suffix"
godoc -url http://localhost:6060/pkg/$pkg | tail -n +2 > $suffix.html

# Munge file locations for GH Pages
# Note: for MacOS there needs to be an empty string after the -i flag
sed -i "s@/lib/godoc/@/$suffix/lib/godoc/@g" $suffix.html

echo "Generated $pkg.html"
