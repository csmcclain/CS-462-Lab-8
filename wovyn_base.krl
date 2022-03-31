ruleset wovyn_base {


    meta {
        shares get_threshold, get_receiver_of_sms
    }

    // Define global variables.
    global {
        sender_of_sms = meta:rulesetConfig{"smsSender"}.klog("sender of sms configure to ")
        get_threshold = function() {
            ent:temperature_threshold == null => 75 | ent:temperature_threshold
        }
        get_receiver_of_sms = function() {
            ent:receiver_of_sms == null => "8013191995" | ent:receiver_of_sms
        }
    }


    rule process_heartbeet {
        // Define when rule is selected
        select when wovyn heartbeat

        // Set variables that are be needed (prelude)
        pre {
            genericThing = event:attrs{"genericThing"}.klog("Received genericThing: ")
            time = time:now().klog("Read time at: ")
        }        

        // Define the action to be taken (action)
        // Action will not be taken when when genericThing is null
        if (genericThing) then noop()

        // Clean up based on what happened (postlude)
        // Postlude will be evaluated if the action above (noop) is fired
        fired {
            raise wovyn event "new_temperature_reading" attributes {
                "temperature": genericThing{"data"}{"temperature"}[0]{"temperatureF"},
                "timestamp": time
            }
        }
    }

    rule find_high_temps {
        // Define when the rule is selected
        select when wovyn new_temperature_reading

        // Set variables that are needed (prelude)
        pre {
            temperature = event:attrs{"temperature"}.klog("Received the following temperature in find_high_temps: ")
            timestamp = event:attrs{"timestamp"}
            threshold = ent:temperature_threshold == null => 75 | ent:temperature_threshold
        }

        // Action will be taken depending if the temperature exceeds the threshold
        if (temperature >= threshold) then noop()

        //Postlude will be evaulated if the action is fired
        fired {
            raise wovyn event "threshold_violation" attributes {
                "temperature": temperature,
                "timestamp": timestamp
            }
        }
    }

    rule threshold_notification {
        // Define when the rule is selected
        select when wovyn threshold_violation

        // Set variables that are needed (prelude)
        pre {
            message = "A reading of " + event:attrs{"temperature"} + " was read at " + event:attrs{"timestamp"}
            receiver = ent:receiver_of_sms == null => "8013191995" | ent:receiver_of_sms
        }

        always {
            raise sensor event "notify_management_of_violation" attributes {
                "message": message,
                "receiver": receiver
            }
        }
        
    }

    rule configuration_change {
        // Define when rule is selected
        select when wovyn configuration_change

        // Set variables that are needed (prelude)
        pre {
            receiver = event:attrs{"smsReceiver"}.klog("Set receiver_of_sms to: ")
            temperature = event:attrs{"threshold"}.klog("Set temperature_threshold to: ")
        }

        always {
            ent:temperature_threshold := temperature
            ent:receiver_of_sms := receiver
        }
    }

}