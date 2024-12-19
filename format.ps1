Get-ChildItem -Path .\src, .\include, .\test, .\example -Include *.hpp, *.cpp -Recurse |
ForEach-Object {
    Write-Output $_.FullName
    &clang-format -i -style=file $_.FullName
}
