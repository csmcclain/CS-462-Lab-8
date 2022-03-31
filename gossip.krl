ruleset gossip {

    meta {
        use module io.picolabs.wrangler alias wrangler
        use module io.picolabs.subscription alias subs
        shares get_events, get_temp_logs, get_own_tracker, get_smart_tracker, get_peer_to_rx
    }

    global {
        get_events = function() {
            schedule:list()
        }
        get_temp_logs = function() {
            ent:temp_logs
        }

        get_own_tracker = function() {
            ent:own_tracker
        }

        get_smart_tracker = function() {
            ent:smart_tracker
        }

        get_peer_to_rx = function() {
            ent:peer_to_rx
        }
    }

    // Init related rules
    rule init {
        select when wrangler ruleset_installed

        always {
            ent:n := 5
            ent:origin_ID := wrangler:name()
            ent:sequence_num := 0

            ent:own_tracker := {}
            ent:temp_logs := {}

            ent:smart_tracker := {}
            ent:peer_to_rx := {}            
        }
    }

    // Heartbeat related rules
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

    // Peer connection related rules

    rule make_connection_to_peer {
        select when gossip make_connection_to_peer
        pre {
            well_known_rx = event:attrs{"wellKnown_rx"}
        }

        event:send({
            "eci": subs:wellKnown_Rx(){"id"},
            "domain":"wrangler", "name":"subscription",
            "attrs": {
                "wellKnown_Tx": well_known_rx,
                "Rx_role":"node", "Tx_role":"node",
                "channel_type": "subscription",
                "node_name": ent:origin_ID
            }
        })
    }

    rule accept_conection_to_peer {
        select when wrangler inbound_pending_subscription_added
        pre {
            their_origin_id = event:attrs{"node_name"}
            attrs = event:attrs.set("node_name", ent:origin_ID)
            my_role = event:attrs{"Rx_role"}
            their_role = event:attrs{"Tx_role"}
        }
        if my_role=="node" && their_role=="node" then noop()
        fired {
            
            raise wrangler event "pending_subscription_approval"
                attributes attrs
            ent:peer_to_rx{their_origin_id} := event:attrs{"Tx"}
            ent:smart_tracker{their_origin_id} := {}
            ent:temp_logs{their_origin_id} := {}
        }
    }

    rule peer_connection_accepted {
        select when wrangler subscription_added

        pre {
            their_origin_id = event:attrs{"node_name"}
            my_role = event:attrs{"Rx_role"}
            their_role = event:attrs{"Tx_role"}
        }

        if my_role == "node" && their_role == "node" then noop()

        fired {
            ent:peer_to_rx{their_origin_id} := event:attrs{"Tx"}
            ent:smart_tracker{their_origin_id} := {}
            ent:temp_logs{their_origin_id} := {}
        }
    }
}