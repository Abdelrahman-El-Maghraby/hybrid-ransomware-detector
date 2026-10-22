/*
    ransomware_generic.yar
    Original, generic ransomware-indicator rules for the Hybrid Ransomware
    Detection System. Written from scratch as structural heuristics, NOT copied
    from any third-party rule pack. They favour *combinations* of indicators to
    keep false positives low, and each rule carries a `severity` meta that the
    scoring matrix reads to weight the match.

    These are intentionally broad triage heuristics, not high-fidelity family
    signatures. Tune or extend them for your own environment.
*/

rule Ransom_Note_Language
{
    meta:
        author      = "hybrid-ransomware-detector"
        description = "Vocabulary typical of a ransom note (files encrypted + how to pay)"
        severity    = "medium"
    strings:
        $enc1 = "your files have been encrypted" nocase wide ascii
        $enc2 = "all your files are encrypted"   nocase wide ascii
        $enc3 = "files have been locked"          nocase wide ascii
        $pay1 = "decryption key"                  nocase wide ascii
        $pay2 = "decrypt your files"              nocase wide ascii
        $pay3 = "restore your files"              nocase wide ascii
        $pay4 = "recovery key"                    nocase wide ascii
        $cur1 = "bitcoin"                         nocase wide ascii
        $cur2 = "btc wallet"                      nocase wide ascii
        $cur3 = "monero"                          nocase wide ascii
    condition:
        // at least one "encrypted" phrase AND one "how to recover/pay" phrase
        (any of ($enc*)) and (any of ($pay*) or any of ($cur*))
}

rule Crypto_Ransom_Extortion_Combo
{
    meta:
        author      = "hybrid-ransomware-detector"
        description = "Encryption claim + payment demand + urgency/deadline"
        severity    = "high"
    strings:
        $e1 = "encrypted"        nocase wide ascii
        $e2 = "encryption"       nocase wide ascii
        $p1 = "pay"              nocase wide ascii
        $p2 = "payment"          nocase wide ascii
        $p3 = "ransom"           nocase wide ascii
        $u1 = "within 24 hours"  nocase wide ascii
        $u2 = "within 48 hours"  nocase wide ascii
        $u3 = "deadline"         nocase wide ascii
        $u4 = "permanently delete" nocase wide ascii
        $u5 = "lost forever"     nocase wide ascii
        $y1 = "your files"       nocase wide ascii
        $y2 = "your data"        nocase wide ascii
        $y3 = "your network"     nocase wide ascii
        $y4 = "your documents"   nocase wide ascii
        $r1 = "decrypt"          nocase wide ascii
        $r2 = "bitcoin"          nocase wide ascii
        $r3 = "monero"           nocase wide ascii
        $r4 = ".onion"           nocase wide ascii
    condition:
        // 4.4.0-beta.2: addressed to the victim ("your files ...") and note-sized;
        // dictionaries and licences contain every one of the other words.
        filesize < 2MB and (any of ($e*)) and (any of ($p*)) and (any of ($u*))
        and (any of ($y*)) and ($p3 or any of ($r*))   // translation bundles have the rest
}

rule Bitcoin_Address_With_Payment_Context
{
    meta:
        author      = "hybrid-ransomware-detector"
        description = "A Bitcoin address string alongside payment/decrypt wording"
        severity    = "medium"
    strings:
        // Legacy (1/3...) and bech32 (bc1...) Bitcoin address shapes.
        $btc = /\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b/ ascii wide
        $ctx1 = "send"     nocase wide ascii
        $ctx2 = "pay"      nocase wide ascii
        $ctx3 = "wallet"   nocase wide ascii
        $ctx4 = "decrypt"  nocase wide ascii
        $coin1 = "bitcoin" nocase wide ascii
        $coin2 = "btc"     nocase wide ascii fullword
    condition:
        // 4.4.0-beta.2: the address shape alone matches random identifiers in
        // documentation and binaries, so the currency must be named as well.
        // 4.4.0-beta.3: "btc", "pay" and "send" also turn up by chance inside the
        // base64 of an e-mail attachment, next to address-shaped runs; a bare
        // "BTC" now needs a ransom word (wallet / decrypt) too.
        filesize < 5MB and $btc and (any of ($ctx*))
        and ($coin1 or ($coin2 and ($ctx3 or $ctx4)))
}

rule PowerShell_Download_Cradle
{
    meta:
        author      = "hybrid-ransomware-detector"
        description = "Encoded / fileless PowerShell download-and-execute cradle"
        severity    = "high"
    strings:
        $ps   = "powershell" nocase wide ascii
        $enc  = /powershell(\.exe)?[^\r\n]{0,80}\s-(e|en|enc|encodedcommand)\s+[A-Za-z0-9+\/=]{20,}/ nocase ascii wide
        $enc2 = "-encodedcommand" nocase wide ascii
        $dl1  = "downloadstring"  nocase wide ascii
        $dl2  = "downloadfile"    nocase wide ascii
        $dl3  = "invoke-webrequest" nocase wide ascii
        $iex  = "iex"             nocase wide ascii fullword
        $b64  = "frombase64string" nocase wide ascii
        $hid  = "-windowstyle hidden" nocase wide ascii
    condition:
        // 4.4.0-beta.2: "-enc" must be followed by an encoded blob and "iex" must be
        // a word (both appeared in shell documentation); an option alone is not a cradle.
        $enc or ($ps and (any of ($dl1, $dl2, $dl3, $b64)) and (any of ($iex, $hid, $enc2, $dl1, $dl2)))
}
