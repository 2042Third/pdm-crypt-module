grep "src" $2 > $1
sed 's/^.*\(src\)\(.*\)$/\2/' $1