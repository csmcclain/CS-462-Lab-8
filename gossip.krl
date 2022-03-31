ruleset gossip {

    meta {
        shares get_events
    }

    global {
        get_events = function() {
            schedule:list()
        }
    }

    rule init {
        select when wrangler ruleset_installed

        always {
            ent:n := 5
        }
    }

    rule start_gossip_beat {
        select when gossip start_beat

        pre {
            n = event:attrs{"beat_time"} == "" =>  ent:n.klog("got n ") | event:attrs{"beat_time"}.klog("got beat ")
        }

        always {
            schedule gossip event "heartbeat" repeat << */#{n} * * * * * >>
        }
    }

    rule stop_gossip_beat {
        select when gossip stop_beat

        pre {
            id = event:attrs{"id"}
        }

        if (id) then schedule:remove(id)
    }

}