ruleset twilio.api {
    meta {
        name "Csmcclain's Twilio Api"
        configure using
            accountSid = ""
            authToken = ""
        provides sendSMS, messages
    }

    global {
        sendSMS =  defaction(receiver, sender, msg) {
            http:post(
                <<https://#{accountSid}:#{authToken}@api.twilio.com/2010-04-01/Accounts/#{accountSid}/Messages.json>>,
                form = {
                  "To": receiver,
                  "From": sender, 
                  "Body": msg
                }) setting(response)
        }

        messages = function (receiver, sender, pageSize) {
            response = http:get(
                <<https://#{accountSid}:#{authToken}@api.twilio.com/2010-04-01/Accounts/#{accountSid}/Messages.json>>,
                qs = {
                    "To": receiver || null,
                    "From": sender || null,
                    "PageSize": pageSize || null
                }
            )
            response{"content"}.decode()
        }
    }
}