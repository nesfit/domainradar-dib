const pipeline = [
    // Remove the unused fields in domain RDAP objects
    {
        $unset: ["rdap.rir", "rdap.type", "rdap.parent_handle"]
    },
    // Remove all IP addresses that do not come from A/AAAA/CNAME DNS records
    {
        $set: {
            "ip_data": {
                $filter: {
                    input: { $ifNull: ["$ip_data", []] },
                    as: "ip",
                    cond: { $in: [ "$$ip.from_record", [ "A", "AAAA", "CNAME" ] ] }
                }
            },
        }
    },
    {
        $set: {
            // Add all the evaluated DNS RRtypes properties to all entries so that "the RRtype was not found" 
            // state is represented by null instead of a missing property.
            "dns": {
                $mergeObjects: [
                    {
                        A: null,
                        AAAA: null,
                        CNAME: null,
                        MX: null,
                        NS: null,
                        TXT: null,
                        SOA: null,
                        zone_SOA: null
                    },
                    "$dns"
                ]
            },
            // Replace empty "ip_data" arrays with nulls
            // (so that the fact of "something is missing" is consistently represented by a null).
            "ip_data": {
                $cond: {
                    if: {
                        $and: [
                            { $ne: ["$ip_data", null] },
                            { $ne: [{ $size: "$ip_data" }, 0] }
                        ]
                    },
                    then: "$ip_data",
                    else: null
                }
            },
            // Fix the "common_name" attribute in the certificate objects
            "tls.certificates": {
                $cond: {
                    if: {
                        $and: [
                            { $ne: [{ $type: "$tls.certificates" }, 'missing'] },
                            { $ne: ["$tls.certificates", null] },
                            { $ne: [{ $size: "$tls.certificates" }, 0] }
                        ]
                    },
                    then: {
                        $map: {
                            input: "$tls.certificates",
                            as: "certificate",
                            in: {
                                $mergeObjects: [
                                    "$$certificate",
                                    {
                                        common_name: {
                                            $cond: {
                                                if: { $ne: [ "$$certificate.common_name", null ] },
                                                then: {
                                                    $substr: [
                                                      "$$certificate.common_name",
                                                      0,
                                                      { $subtract: [{ $strLenCP: "$$certificate.common_name" }, 2] }
                                                    ]
                                                },
                                                else: null
                                            }
                                        }
                                    }
                                ]
                            }
                        }
                    },
                    else: null
                }
            }
        }
    },
    // Fix "tls" fields that were originally null but now are "tls": { "certificates": null } due to the above map
    {
        $set: {
            "tls": {
                $cond: {
                    if: { $ne: [ "$tls", {certificates: null} ] },
                    then: "$tls",
                    else: null
                }
            }
        }
    },
    // Remove the unused fields in IP records
    {
        $unset: [ "ip_data.rep", "ip_data.ports", "ip_data.remarks.rep_evaluated_on", "ip_data.remarks.ports_scanned_on" ]
    },
];

const toFix = [ "phishing_2406_strict", "umbrella_benign_FINISHED", "benign_2312_anonymized", "malware_2406_strict" ];
for (let collectionName of toFix) {
    let newName = collectionName + "_BEFORE_DATA_FIX";
    
    db.getCollection(collectionName).renameCollection(newName);
    db.getCollection(newName).aggregate(pipeline.concat([
        {
            $out: collectionName
        }
    ]));
    db.getCollection(collectionName).createIndex({"domain_name": 1}, {unique: true});
}
