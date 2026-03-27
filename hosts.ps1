1..254 | ForEach-Object {
    $ip = "192.168.0.$_"
    $result = ping -n 1 -w 500 $ip 2>$null
    if ($result -match "Reply from $ip") {
        Write-Host "$ip is up"
    }
}