rule ToolsFiles {
    meta:
        description = "Detect utilities related to a potential Warp-Panda activity"
        author = "0xArrow"
        reference = "https://www.crowdstrike.com/en-us/blog/warp-panda-cloud-threats/"
    condition:
        hash.sha256(0, filesize) == "40db68331cb52dd3ffa0698144d1e6919779ff432e2e80c058e41f7b93cec042" or // GuestConduit SHA256 hash
        hash.sha256(0, filesize) == "88db1d63dbd18469136bf9980858eb5fc0d4e41902bf3e4a8e08d7b6896654ed" or // Junction SHA256 hash
        hash.sha256(0, filesize) == "9a0e1b7a5f7793a8a5a62748b7aa4786d35fc38de607fb3bb8583ea2f7974806" or // Junction SHA256 hash
        hash.sha256(0, filesize) == "40992f53effc60f5e7edea632c48736ded9a2ca59fb4924eb6af0a078b74d557" // BRICKSTORM SHA256 hash
}

rule NetworkIndicators {
    meta:
        description = "Detect network-based indicators associated with Warp-Panda"
        author = "0xArrow"
        reference = "https://www.crowdstrike.com/en-us/blog/warp-panda-cloud-threats/"
    strings:
        $ip1 = "208.83.233.14" // IP address leveraged by WARP PANDA
        $ip2 = "149.28.120.31" // IP address leveraged by WARP PANDA
    condition:
        any of them
}