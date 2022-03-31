ruleset management_profile {

    meta {
        use module twilio.api alias twilio
        with
            accountSid = meta:rulesetConfig{"accountSid"}
            authToken = meta:rulesetConfig{"authToken"}
    }

    global {
        sender_of_sms = meta:rulesetConfig{"sms_sender"}
    }

    rule raise_threshold_notificaiton {
        select when management alert_threshold 

        pre {
            receiver = event:attrs{"receiver"}
            message = event:attrs{"message"}
        } 

        twilio:sendSMS(receiver, sender_of_sms, message)
    }
}