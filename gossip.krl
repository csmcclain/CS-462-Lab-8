ruleset gossip {

    meta {
        use module io.picolabs.wrangler alias wrangler
        use module io.picolabs.subscription alias subs
        shares get_events, get_temp_logs, get_own_tracker, get_smart_tracker, get_peer_to_send_to, get_peer_to_rx,
            get_origins_unsent_to_peer, split_string, get_rumor_message, get_message_to_send, get_seen_message
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

        generate_rumor_message = function(read_temperature, read_time) {
            {
                "MessageID" : ent:origin_ID + ":" + ent:sequence_num,
                "SensorID": ent:origin_ID,
                "Temperature": read_temperature,
                "Timestamp": read_time
            }
        }

        get_peer_to_send_to = function() {
            // Grab a random peer!
            n = random:integer(lower = 0, upper = ent:peer_to_rx.length() - 1)
            ent:peer_to_rx.keys()[n]
        }

        get_origins_unsent_to_peer = function(peer) {
            peer_data = ent:smart_tracker{peer}
            not_in_peers_map = ent:own_tracker.filter(function(v,k) {
                peer_data{k} == null
            });

            return (not_in_peers_map.length() > 0) => not_in_peers_map.keys()[0] | null
        }

        determine_lartest_defecit = function(peer) {
            peer_data = ent:smart_tracker{peer}
            values_to_update = ent:own_tracker.filter(function(v,k) {
                peer_data{k} < v
            });

            return (values_to_update.length() > 0) => values_to_update.keys()[0] | null
        }

        split_string = function(string_to_split) {
            split_string = string_to_split.split(re#:#)
            split_string[split_string.length() - 1].as("Number")
        }

        get_rumor_message = function(peer, origin_to_send) {
            // Build the message
            last_seen_by_peer = ent:smart_tracker{[peer, origin_to_send]} != null => ent:smart_tracker{[peer, origin_to_send]}.klog("starting at ") | -1.klog("No seen by peer ")
            origin_messages = ent:temp_logs{origin_to_send}
            payload = origin_messages.filter(function(v,k) {
                // K will be the origin_ID:value_to_compare_to
                split_string(k) > last_seen_by_peer
            })

            return {
                "message_type": "rumor",
                "message_payload": payload,
                "message_origin": origin_to_send,
                "peer_sent_to": peer
            }
        }

        get_seen_message = function() {
            return {
                "message_type": "seen",
                "message_sender": ent:origin_ID,
                "message_payload": ent:own_tracker
            }
        }

        get_message_to_send = function(peer) {
            // First check to see if we have origin data that our peer doesn't have
            unseen_origin_id_by_peer = get_origins_unsent_to_peer(peer)

            // If there were no unsent origins, check if any messages haven't been passed along
            final_rumor_message_check = (unseen_origin_id_by_peer != null) => unseen_origin_id_by_peer | determine_lartest_defecit(peer)

            updates_to_send = (final_rumor_message_check != null) => get_rumor_message(peer, final_rumor_message_check) | get_seen_message()
            // Now Determine what kind of message to Send
            updates_to_send
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
            
            raise gossip event "add_peer" attributes event:attrs
        }
    }

    rule add_peer_to_storage {
        select when gossip add_peer

        pre {
            their_origin_id = event:attrs{"node_name"}
        }

        if (their_origin_id != ent:origin_ID) then noop();

        fired {
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
            raise gossip event "add_peer" attributes event:attrs
        }
    }

    // Create new rumor Message
    rule process_wovyn_reading {
        select when wovyn heartbeat 

        pre {
            genericThing = event:attrs{"genericThing"}.klog("Received genericThing: ")
            time = time:now().klog("Read time at: ")
        } 

        if (genericThing) then noop()

        fired {
            // Generate and save the message
            message = generate_rumor_message(genericThing{"data"}{"temperature"}[0]{"temperatureF"}, time).klog("Got this message ")
            ent:temp_logs{[ent:origin_ID, message{"MessageID"}]} := message

            // Update my own table
            ent:own_tracker{ent:origin_ID} := ent:sequence_num

            // progress the sequence num 
            ent:sequence_num := ent:sequence_num + 1
        }
    }

    rule process_gossip_heartbeat {
        select when gossip heartbeat

        pre {
            // Determine which peer to send to
            peer_to_send_to = get_peer_to_send_to().klog("Going to send to peer ")
            rx_to_send_to = ent:peer_to_rx{peer_to_send_to}

            // Determine which message to send
            message_blob = get_message_to_send(peer_to_send_to)
        }

        // Send the message
        event:send({
            "eci": rx_to_send_to,
            "domain": "gossip", "type": message_blob{"message_type"},
            "eid": "gossiping",
            "attrs": message_blob
        });

        // Update my state
        fired {
            raise gossip event "update_state" attributes {
                "peer": peer_to_send_to,
                "update": message_blob
            }
        }
    }

    rule process_state_update {
        select when gossip update_state

        pre {
            peer_sent_to = event:attrs{"peer_sent_to"}
            payload = event:attrs{"message_payload"}
            origin_id_sent = event:attrs{"message_origin"}
        }

        if (peer_sent_to != null) then noop()

        fired {
            ent:smart_tracker{[peer_sent_to, origin_id_sent]} := event:attrs{"message_payload"}.length() - 1
        }
    }

    rule process_rumor {
        select when gossip rumor 

        pre {
            messages = event:attrs{"message_payload"}
            origin = event:attrs{"message_origin"}
        }

        always {
            // Update my logs
            ent:temp_logs{origin} := ent:temp_logs{origin}.put(messages)
            // Update my seen table
            ent:own_tracker{origin} := ent:temp_logs{origin}.length() - 1
        }

    }
}