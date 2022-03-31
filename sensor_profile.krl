ruleset sensor_profile {

    meta {
        use module io.picolabs.wrangler alias wrangler
        use module io.picolabs.subscription alias subs
        shares get_sensor_info
    }

    //Define global variables/functions
    global {
        get_sensor_info = function() {
            {
                "location": ent:location == null => "Not Configured" | ent:location,
                "name": ent:name == null => "Not Configured" | ent:name,
                "SMS_receiver": ent:smsReceiver == null => "0000000000" | ent:smsReceiver,
                "threshold": ent:threshold == null => 75 | ent:threshold
            }
        }
    }

    rule process_profile_update {
        // Define when rule is selected
        select when sensor profile_update

        // Set variables that are needed (prelude)
        pre {
            location = event:attrs{"location"}.klog("Received new location: ")
            name = event:attrs{"name"}.klog("Received new name: ")
            smsReceiver = event:attrs{"SMS_receiver"}.klog("Received new sms number: ")
            threshold = event:attrs{"threshold"}.klog("Received new threshold: ")
        }

        always {
            ent:location := location;
            ent:name := name;
            ent:smsReceiver := smsReceiver;
            ent:threshold := threshold;

            raise wovyn event "configuration_change" attributes {
                "smsReceiver": smsReceiver,
                "threshold": threshold
            }
        }
    }

    rule send_wellknown_to_parent {
        select when wrangler ruleset_installed
            where event:attrs{"rids"} >< meta:rid

        pre {
            pico_name = event:attrs{"name"}
            parent_eci = wrangler:parent_eci()
            my_eci = wrangler:myself(){"eci"}
            wellKnown_eci = subs:wellKnown_Rx(){"id"}
        }
        event:send({
            "eci": parent_eci,
            "domain": "sensor", "type": "identify",
            "attrs": {
                "name": pico_name,
                "wellKnown_eci": wellKnown_eci,
                "eci": my_eci
            }
        })

        always {
            ent:name := pico_name
        }
    }

    rule accept_subscriptions {
        select when wrangler inbound_pending_subscription_added
        pre {
            my_role = event:attrs{"Rx_role"}
            their_role = event:attrs{"Tx_role"}
        }
        if my_role=="Sensor" && their_role=="Manager" then noop()
        fired {
            raise wrangler event "pending_subscription_approval"
                attributes event:attrs
            ent:subscriptionTx := event:attr("Tx")
        } else {
            raise wrangler event "inbound_rejection"
                attributes event:attrs
        }
    }

    rule notify_management {
        select when sensor notify_management_of_violation

        event:send({"eci": ent:subscriptionTx,
            "domain": "management", "type": "alert_threshold",
            "eid": "threshold-violation",
            "attrs": event:attrs
        })
    }

    // Beginning of Lab 7

    rule generate_report {
        select when management generate_report
        pre {
            eci = ent:subscriptionTx
            correlationID = event:attrs{"correlationID"}.klog("Got correlation ")
            recent_reading = ent:last_temp_reading.klog("most recent reading ")
            rx_channel = subs:wellKnown_Rx(){"id"}.klog("Got channel ")
        }
        event:send(
            {
                "eci": eci,
                "eid": "scatter-response",
                "domain": "management", "type": "sensor_report",
                "attrs": {
                    "correlationID": correlationID,
                    "report": {
                        "name": wrangler:name(),
                        "pico_rx_channel": rx_channel,
                        "latest_temperature_reading": recent_reading
                    }
                }
            }
        )
    }

    rule most_recent_reading {
        select when wovyn new_temperature_reading
        always {
            ent:last_temp_reading := event:attrs{"temperature"}
        }
    }
}