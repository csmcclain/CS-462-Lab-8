ruleset manage_sensors {

    meta {

        use module io.picolabs.wrangler alias wrangler
        use module io.picolabs.subscription alias subs
        shares sensors, get_temperatures, get_sub_data, get_reports
        provides get_sub_data  
    }

    global {

        sensors = function() {
            ent:sensors
        }

        generate_name = function() {
            <<Sensor #{random:uuid}>>
        }

        get_sub_data = function() {
            ent:subscription_data
        }

        get_temperatures = function() {
            ent:subscription_data.values().map(function(tx) {
                eci = tx
                wrangler:picoQuery(eci, "temperature_store", "temperatures")
            })
        }

        get_reports = function() {
            ent:reports
        }

        defaultThreshold = 75
        defaultSMSReceiver = "8013191995"
    }

    rule init {
        select when wrangler ruleset_installed

        if (ent:sensors) then noop()
        
        notfired {
          ent:sensors := {}
          ent:subscription_data := {}
        }
    }

    rule add_sensor {
        select when sensor new_sensor

        pre {
            newSensorName = generate_name()
            exists = ent:sensors{newSensorName} != null
        }

        if (exists) then noop()

        notfired {
            raise wrangler event "new_child_request" attributes {
                "name": newSensorName,
                "backgroundColor": "#ffa500"
            }
        }
    }

    rule new_sensor_created {
        select when wrangler new_child_created

        pre {
            name = event:attrs{"name"}.klog("sensor_created new child name: ")
            childID = event:attrs{"eci"}.klog("new child eci: ")
        }

        if name && childID then noop()

    }

    rule initialize_picolabs_emitter_ruleset {
        select when wrangler new_child_created

        pre {
            eci = event:attrs{"eci"}
        }

        event:send(
            {
                "eci": eci,
                "eid": "install-ruleset",
                "domain": "wrangler", "type": "install_ruleset_request",
                "attrs": {
                    "absoluteURL": meta:rulesetURI,
                    "rid": "io.picolabs.wovyn.emitter",
                    "config": {}
                }
            }
        )
    }

    rule initialize_wovyn_ruleset {
        select when wrangler new_child_created

        pre {
            eci = event:attrs{"eci"}
        }

        event:send(
            {
                "eci": eci,
                "eid": "install-ruleset",
                "domain": "wrangler", "type": "install_ruleset_request",
                "attrs": {
                    "absoluteURL": meta:rulesetURI,
                    "rid": "wovyn_base",
                    "config": {}
                }
            }
        )
    }

    rule initialize_temperature_store_ruleset {
        select when wrangler new_child_created

        pre {
            eci = event:attrs{"eci"}
        }

        event:send(
            {
                "eci": eci,
                "eid": "install-ruleset",
                "domain": "wrangler", "type": "install_ruleset_request",
                "attrs": {
                    "absoluteURL": meta:rulesetURI,
                    "rid": "temperature_store",
                    "config": {}
                }
            }
        )
    }

    rule initialize_gossip_ruleset {
        select when wrangler new_child_created

        pre {
            eci = event:attrs{"eci"}
        }

        event:send(
            {
                "eci": eci,
                "eid": "install-ruleset",
                "domain": "wrangler", "type": "install_ruleset_request",
                "attrs": {
                    "absoluteURL": meta:rulesetURI,
                    "rid": "gossip",
                    "config": {}
                }
            }
        )
    }
    
    rule initialize_sensor_profile_ruleset {
        select when wrangler new_child_created

        pre {
            name = event:attrs{"name"}
            eci = event:attrs{"eci"}
        }

        event:send(
            {
                "eci": eci,
                "eid": "install-ruleset",
                "domain": "wrangler", "type": "install_ruleset_request",
                "attrs": {
                    "absoluteURL": meta:rulesetURI,
                    "rid": "sensor_profile",
                    "config": {},
                    "name": name
                }
            }
        )
    }

    rule configure_child_sensor_profile{
        select when wrangler child_initialized

        pre {
            eci = event:attrs{"eci"}
            name = event:attrs{"name"}
        }

        event:send(
            {
                "eci": eci,
                "eid": "configure-ruleset",
                "domain": "sensor", "type": "profile_update",
                "attrs": {
                    "SMS_receiver": defaultSMSReceiver,
                    "threshold": defaultThreshold,
                    "location": "unspecified",
                    "name": name
                }
            }
        )
    }

    rule remove_sensor {
        select when sensor unneeded_sensor

        pre {
            sensorName = event:attrs{"name"}.klog("received sensor name to remove: ")
            eci = ent:sensors{sensorName}{"eci"}
            exists = ent:sensors && eci != null
        }

        if exists then noop()

        fired {
            raise wrangler event "child_deletion_request" attributes {
                "eci": eci
            }
            clear ent:sensors{sensorName}
        }
    }

    rule flush_sensors {
        select when sensor flush_sensors

        always {
            ent:sensors := {}
            ent:subscription_data := {}
        }
    }

    rule identify_child_wellknown {
        select when sensor identify

        pre {
            name = event:attrs{"name"}
            eci = event:attrs{"eci"}.klog("Now got eci for child: ")
            wellKnown = event:attrs{"wellKnown_eci"}
        }

        always {
            ent:sensors{name} := {
                "eci": eci,
                "wellKnown_eci": wellKnown
            }

            // Raise an event to create a subscription with new child
            raise manage_sensors event "sensor_subscription_request" attributes {
                "sensor_name": name
            }
        }
    }

    rule create_sensor_subscription {
        select when manage_sensors sensor_subscription_request

        pre {
            sensor_name = event:attrs{"sensor_name"}
            sensor_wellKnown_Rx = event:attrs{"wellKnown_Rx"} == null => ent:sensors{sensor_name}{"wellKnown_eci"} | event:attrs{"wellKnown_Rx"}
        }

        event:send({"eci": subs:wellKnown_Rx(){"id"},
            "domain":"wrangler", "name":"subscription",
            "attrs": {
                "wellKnown_Tx":sensor_wellKnown_Rx,
                "Rx_role":"Manager", "Tx_role":"Sensor",
                "name": sensor_name+"-subscription", "channel_type":"subscription"
            }
        })
    }

    rule accept_subscriptions {
        select when wrangler inbound_pending_subscription_added
        pre {
            my_role = event:attrs{"Rx_role"}
            their_role = event:attrs{"Tx_role"}
        }
        if my_role=="Manager" && their_role=="Manager w/o picos" then noop()
        fired {
            raise wrangler event "pending_subscription_approval"
                attributes event:attrs
        }
    }

    rule get_subscription_role {
        select when wrangler subscription_added
        pre {
            tx_role = event:attrs{"Tx_role"}
            rx_role = event:attrs{"Rx_role"}
            tx = event:attrs{"Tx"}
        }
        if tx_role == "Manager" && rx_role == "Sensor" then noop()

        fired {
            ent:subscription_data{event:attrs{"Id"}} := tx
        }
    }

    rule introduce_manager_and_sensor {
        select when manage_sensors add_request
        pre {
            sensor_name = event:attrs{"sensor_name"}
            name = event:attrs{"name"}
        }

        event:send({"eci": ent:sensors{[sensor_name, "wellKnown_eci"]},
            "domain": "wrangler", "name":"subscription",
            "attrs": {
                "wellKnown_Tx": event:attrs{"wellKnown_Tx"},
                "Rx_role":"Manager", "Tx_role":"Sensor",
                "name": name+"-subscription", "channel_type":"subscription"
            }
        })
    }

    // Begining of Lab 7

    rule init_lab_seven {
        select when wrangler ruleset_installed

        if (ent:report) then noop()
        
        notfired {
          ent:report := 0
          ent:reports := {}
        }
    }

    rule reset_report_ids {
        select when management reset_report_ids
        always {
            ent:report := 0
            ent:reports := {}
        }
    }

    rule begin_report_collection {
        select when management begin_new_report
        foreach get_sub_data() setting (tx, sensor)
            pre {
                sensorId = sensor.klog("Now processing sensor ")
                eci = tx.klog("with tx ")
                num_sensors = get_sub_data().keys().length().klog("num sensors ")
                correlationID = ent:report.as("String")
            }

            event:send(
                {
                    "eci": eci,
                    "eid": "scatter-temperatures",
                    "domain": "management", "type": "generate_report",
                    "attrs": {
                        "correlationID": correlationID
                    }
                }
            )

            fired {
                ent:reports{correlationID} := {
                    "temperature_sensors": num_sensors,
                    "responding": 0,
                    "temperatures": []
                } on final
                ent:report := ent:report + 1 on final
            }
    }

    rule process_sensor_report {
        select when management sensor_report
        pre {
            correlationID = event:attrs{"correlationID"}.klog("Got correlation report ")
            pico_report = event:attrs{"report"}.klog("got report ")
            total_report = ent:reports{correlationID}.klog("Found report ")
            temperatures = total_report{"temperatures"}.append(pico_report).klog("Total temps recorded ")
        }
        always {
            ent:reports{correlationID} := {
                "temperature_sensors": total_report{"temperature_sensors"},
                "responding": total_report{"responding"} + 1,
                "temperatures": temperatures
            }
        }
    }
}