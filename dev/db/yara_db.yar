rule EICARTestFile!yar {
    meta:
        description = "EICAR test file string (full)"

    strings:
        $s = /^X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H\+H\*\s*$/

    condition:
        all of them
}

rule Susp:EICARTestFile!yar {
    meta:
        description = "EICAR test file string (shortened)"

    strings:
        $s = "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"

    condition:
        all of them
}
