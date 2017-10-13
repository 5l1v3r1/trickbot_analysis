# TrickBot Webinar - October 13, 2017
# Aaron Eppert 

module TRICKBOT_DETECT;

export {
    redef enum Notice::Type += {
        X509_CERT
    };

    const trickbot_issuer = set("rvgvtfdf") &redef;
}

event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate)
{
    if ( cert?$cn && cert$cn in trickbot_issuer ) {
        for ( cid in f$conns ) {
            NOTICE([$note=TRICKBOT_DETECT::X509_CERT,
                    $msg=fmt("Possible Trickbot observed - %s", cid$resp_h),
                    $conn=f$conns[cid],
                    $identifier=cat(cid$resp_h)]);
        }
    }
}
