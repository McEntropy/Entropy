use crate::client::AuthenticatedClient;
use crate::entity::player::EntityPlayer;
use crate::server_client_mingle::ClientAction;
use mc_buffer::buffer::PacketWriter;
use mc_buffer::engine::BufferRegistryEngine;
use mc_chat::Chat;
use mc_commands::{Command, NodeStub};
use mc_level::chunk::Chunk;
use mc_level::codec::MinecraftWorldgenBiomeSkyColor::IntCoverage;
use mc_level::codec::{
    Codec, MinecraftChatType, MinecraftChatTypeChat, MinecraftChatTypeElement,
    MinecraftChatTypeElementNarration, MinecraftChatTypeEntry, MinecraftChatTypeStyle,
    MinecraftDimensionType, MinecraftDimensionTypeElement, MinecraftDimensionTypeEntry,
    MinecraftWorldgenBiome, MinecraftWorldgenBiomeEffects, MinecraftWorldgenBiomeElement,
    MinecraftWorldgenBiomeEntry, MinecraftWorldgenBiomeMoodSound, MonsterSpawnLightLevel,
    MonsterSpawnLightLevelRange,
};
use mc_registry::client_bound::play::{
    AddPlayerEntry, ChangeDifficulty, DeclareCommands, DeclareRecipes, Disconnect, EntityEvent,
    JoinGame, LevelChunkData, LevelChunkWithLight, LightUpdate, LightUpdateData, PlayerAbilities,
    PlayerAbilitiesBitMap, PlayerInfo, PlayerPosition, PluginMessage, RecipeBookSettings,
    RecipeState, RelativeArgument, SetCarriedItem, UpdateLatencyEntry, UpdateRecipes, UpdateTags,
};
use mc_registry::shared_types::play::{Difficulty, GameType, ResourceLocation};
use mc_registry::shared_types::MCIdentifiedKey;
use mc_serializer::primitive::VarInt;
use std::io::Cursor;

fn system_level_resource_location() -> ResourceLocation {
    ResourceLocation::from("entropy_level:system")
}

fn system_biome_resource_location() -> ResourceLocation {
    ResourceLocation::from("entropy_biome:system")
}

pub async fn join_client(
    mut engine: BufferRegistryEngine,
    client: AuthenticatedClient,
) -> anyhow::Result<()> {
    // player's entity ID is always (0), because I can
    let player_self = EntityPlayer::new(client.profile.clone(), 0);

    let join_game = JoinGame {
        player_id: player_self.entity_id(),
        hardcore: false,
        game_type: GameType::Survival,
        previous_game_type: GameType::None,
        levels: (VarInt::from(1), vec![system_level_resource_location()]),
        codec: Codec {
            dimension_registry: MinecraftDimensionType {
                value: vec![MinecraftDimensionTypeEntry {
                    id: 0,
                    name: system_level_resource_location().to_string(),
                    element: MinecraftDimensionTypeElement {
                        respawn_anchor_works: 0,
                        fixed_time: None,
                        has_raids: 0,
                        effects: "minecraft:overworld".to_string(),
                        natural: 1,
                        ambient_light: 0.0,
                        has_skylight: 1,
                        ultrawarm: 0,
                        coordinate_scale: 1.0,
                        infiniburn: "#minecraft:infiniburn_overworld".to_string(),
                        monster_spawn_block_light_limit: 0,
                        has_ceiling: 0,
                        monster_spawn_light_level: MonsterSpawnLightLevel::Complex {
                            type_inner: "minecraft:uniform".to_string(),
                            range: MonsterSpawnLightLevelRange {
                                min_inclusive: 0,
                                max_inclusive: 7,
                            },
                        },
                        bed_works: 1,
                        piglin_safe: 0,
                        logical_height: 384,
                        min_y: -64,
                        height: 384,
                    },
                }],
                type_inner: "minecraft:dimension_type".to_string(),
            },
            biome_registry: MinecraftWorldgenBiome {
                value: vec![MinecraftWorldgenBiomeEntry {
                    element: MinecraftWorldgenBiomeElement {
                        downfall: 0.4,
                        temperature: 0.8,
                        precipitation: "rain".to_string(),
                        temperature_modifier: None,
                        effects: MinecraftWorldgenBiomeEffects {
                            particle: None,
                            ambient_sound: None,
                            music: None,
                            water_fog_color: 329011,
                            grass_color: None,
                            fog_color: 12638463,
                            grass_color_modifier: None,
                            foliage_color: None,
                            water_color: 4159204,
                            additions_sound: None,
                            sky_color: IntCoverage(7907327),
                            mood_sound: MinecraftWorldgenBiomeMoodSound {
                                sound: "minecraft:ambient.cave".to_string(),
                                block_search_extent: 8,
                                offset: 2.0,
                                tick_delay: 6000,
                            },
                        },
                    },
                    name: system_biome_resource_location().to_string(),
                    id: 0,
                }],
                type_inner: "minecraft:worldgen/biome".to_string(),
            },
            chat_registry: MinecraftChatType {
                value: vec![
                    MinecraftChatTypeEntry {
                        element: MinecraftChatTypeElement {
                            chat: MinecraftChatTypeChat {
                                style: None,
                                translation_key: "chat.type.text".to_string(),
                                parameters: vec!["sender".to_string(), "content".to_string()],
                            },
                            narration: MinecraftChatTypeElementNarration {
                                parameters: vec!["sender".to_string(), "content".to_string()],
                                translation_key: "chat.type.text.narrate".to_string(),
                            },
                        },
                        id: 0,
                        name: "minecraft:chat".to_string(),
                    },
                    MinecraftChatTypeEntry {
                        element: MinecraftChatTypeElement {
                            chat: MinecraftChatTypeChat {
                                style: None,
                                translation_key: "chat.type.announcement".to_string(),
                                parameters: vec!["sender".to_string(), "content".to_string()],
                            },
                            narration: MinecraftChatTypeElementNarration {
                                parameters: vec!["sender".to_string(), "content".to_string()],
                                translation_key: "chat.type.text.narrate".to_string(),
                            },
                        },
                        id: 1,
                        name: "minecraft:say_command".to_string(),
                    },
                    MinecraftChatTypeEntry {
                        element: MinecraftChatTypeElement {
                            chat: MinecraftChatTypeChat {
                                style: Some(MinecraftChatTypeStyle {
                                    italic: 1,
                                    color: "gray".to_string(),
                                }),
                                translation_key: "commands.message.display.incoming".to_string(),
                                parameters: vec!["sender".to_string(), "content".to_string()],
                            },
                            narration: MinecraftChatTypeElementNarration {
                                parameters: vec!["sender".to_string(), "content".to_string()],
                                translation_key: "chat.type.text.narrate".to_string(),
                            },
                        },
                        id: 2,
                        name: "minecraft:msg_command_incoming".to_string(),
                    },
                    MinecraftChatTypeEntry {
                        element: MinecraftChatTypeElement {
                            chat: MinecraftChatTypeChat {
                                style: Some(MinecraftChatTypeStyle {
                                    italic: 1,
                                    color: "gray".to_string(),
                                }),
                                translation_key: "commands.message.display.outgoing".to_string(),
                                parameters: vec!["target".to_string(), "content".to_string()],
                            },
                            narration: MinecraftChatTypeElementNarration {
                                parameters: vec!["sender".to_string(), "content".to_string()],
                                translation_key: "chat.type.text.narrate".to_string(),
                            },
                        },
                        id: 3,
                        name: "minecraft:msg_command_outgoing".to_string(),
                    },
                    MinecraftChatTypeEntry {
                        element: MinecraftChatTypeElement {
                            chat: MinecraftChatTypeChat {
                                style: None,
                                translation_key: "chat.type.team.text".to_string(),
                                parameters: vec![
                                    "target".to_string(),
                                    "sender".to_string(),
                                    "content".to_string(),
                                ],
                            },
                            narration: MinecraftChatTypeElementNarration {
                                parameters: vec!["sender".to_string(), "content".to_string()],
                                translation_key: "chat.type.text.narrate".to_string(),
                            },
                        },
                        id: 4,
                        name: "minecraft:team_msg_command_incoming".to_string(),
                    },
                    MinecraftChatTypeEntry {
                        element: MinecraftChatTypeElement {
                            chat: MinecraftChatTypeChat {
                                style: None,
                                translation_key: "chat.type.team.sent".to_string(),
                                parameters: vec![
                                    "target".to_string(),
                                    "sender".to_string(),
                                    "content".to_string(),
                                ],
                            },
                            narration: MinecraftChatTypeElementNarration {
                                parameters: vec!["sender".to_string(), "content".to_string()],
                                translation_key: "chat.type.text.narrate".to_string(),
                            },
                        },
                        id: 5,
                        name: "minecraft:team_msg_command_outgoing".to_string(),
                    },
                    MinecraftChatTypeEntry {
                        element: MinecraftChatTypeElement {
                            chat: MinecraftChatTypeChat {
                                style: None,
                                translation_key: "chat.type.emote".to_string(),
                                parameters: vec!["sender".to_string(), "content".to_string()],
                            },
                            narration: MinecraftChatTypeElementNarration {
                                parameters: vec!["sender".to_string(), "content".to_string()],
                                translation_key: "chat.type.emote".to_string(),
                            },
                        },
                        id: 6,
                        name: "minecraft:emote_command".to_string(),
                    },
                    MinecraftChatTypeEntry {
                        element: MinecraftChatTypeElement {
                            chat: MinecraftChatTypeChat {
                                style: None,
                                translation_key: "%s".to_string(),
                                parameters: vec!["content".to_string()],
                            },
                            narration: MinecraftChatTypeElementNarration {
                                parameters: vec!["content".to_string()],
                                translation_key: "%s".to_string(),
                            },
                        },
                        id: 7,
                        name: "minecraft:raw".to_string(),
                    },
                ],
                type_inner: "minecraft:chat_type".to_string(),
            },
        },
        dimension_type: ResourceLocation::from("dimension:overworld"),
        dimension: ResourceLocation::from("dimension:overworld"),
        seed: 0,
        max_players: 20.into(),
        chunk_radius: 11.into(),
        simulation_distance: 10.into(),
        reduced_debug_info: false,
        show_death_screen: true,
        is_debug: false,
        is_flat: true,
        last_death_location: (false, None),
    };

    println!("Creating brand buf");

    let mut brand_buf = Cursor::new(Vec::new());
    mc_serializer::serde::Serialize::serialize(
        &"KekW Official Server".to_string(),
        &mut brand_buf,
        client.protocol_version(),
    )?;

    println!("Sending plugin message.");

    let server_brand = PluginMessage {
        identifier: ResourceLocation::from("minecraft:brand"),
        data: brand_buf.into_inner(),
    };

    println!("Sending change difficulty");

    let change_difficulty = ChangeDifficulty {
        difficulty: Difficulty::Peaceful,
        locked: true,
    };

    println!("Sending player abilities");

    let player_abilities = PlayerAbilities {
        player_abilities_bits: PlayerAbilitiesBitMap {
            invulnerable: false,
            flying: false,
            can_fly: false,
            instant_build: false,
        },
        flying_speed: 0.05,
        walking_speed: 0.1,
    };
    let set_carried_item = SetCarriedItem { slot: 0 };

    println!("Setting recipes?");

    let update_recipes = UpdateRecipes {
        recipes: (VarInt::from(0), Vec::new()),
    };
    let update_tags = UpdateTags {
        tags: Default::default(),
    };

    println!("Sending join game.");
    engine.send_packet(join_game).await?;
    println!("Sending server brand.");
    engine.send_packet(server_brand).await?;
    println!("Sending change difficulty.");
    engine.send_packet(change_difficulty).await?;
    println!("Sending player abilities.");
    engine.send_packet(player_abilities).await?;
    println!("Sending set carried item.");
    engine.send_packet(set_carried_item).await?;
    println!("Sending update recipes.");
    engine.send_packet(update_recipes).await?;
    println!("Sending update tags.");
    engine.send_packet(update_tags).await?;

    engine
        .send_packet(EntityEvent {
            entity_id: player_self.entity_id(),
            event_id: 24,
        })
        .await?;

    engine
        .send_packet(DeclareCommands {
            commands: (
                VarInt::from(1),
                vec![Command {
                    command_flags: 0,
                    children: (VarInt::from(0), vec![]),
                    redirect: None,
                    node_stub: NodeStub::Root,
                }],
            ),
            root_index: VarInt::from(0),
        })
        .await?;

    engine
        .send_packet(DeclareRecipes {
            state: RecipeState::INIT,
            settings: RecipeBookSettings {
                crafting_open: false,
                crafting_filtering: false,
                furnace_open: false,
                furnace_filtering: false,
                blast_furnace_open: false,
                blast_furnace_filtering: false,
                smoker_open: false,
                smoker_filtering: false,
            },
            recipes: (VarInt::from(0), vec![]),
            to_highlight: (VarInt::from(0), vec![]),
        })
        .await?;

    engine
        .send_packet(PlayerPosition {
            x: 0.0,
            y: 0.0,
            z: 0.0,
            y_rot: 0.0,
            x_rot: 0.0,
            relative_arguments: Default::default(),
            id: VarInt::from(0),
            dismount_vehicle: false,
        })
        .await?;

    engine
        .send_packet(PlayerInfo::AddPlayer((
            VarInt::from(1),
            vec![AddPlayerEntry {
                profile: client.profile.clone(),
                game_type: GameType::Survival,
                latency: VarInt::from(0),
                has_display_name: true,
                display_name: Some(Chat::text(&client.profile.name)),
                key_data: (client.raw_key.is_some(), client.raw_key.as_ref().cloned()),
            }],
        )))
        .await?;

    engine
        .send_packet(PlayerInfo::UpdateLatency((
            VarInt::from(1),
            vec![UpdateLatencyEntry {
                uuid: client.profile.id,
                latency: VarInt::from(0),
            }],
        )))
        .await?;

    for x in -5i32..5 {
        for z in -5i32..5 {
            engine
                .send_packet(LevelChunkWithLight {
                    chunk_data: LevelChunkData {
                        chunk: Chunk::new(x, z),
                        block_entities: (0.into(), vec![]),
                    },
                    data: LightUpdateData {
                        trust_edges: false,
                        sky_y_mask: (0.into(), vec![]),
                        block_y_mask: (0.into(), vec![]),
                        empty_sky_y_mask: (0.into(), vec![]),
                        empty_block_y_mask: (0.into(), vec![]),
                        sky_updates: (0.into(), vec![]),
                        block_updates: (0.into(), vec![]),
                    },
                })
                .await?;
        }
    }

    // send chunks

    println!("Finished all");
    engine
        .send_packet(Disconnect {
            reason: Chat::text("Got Got"),
        })
        .await?;

    // send initial join packet // imagine if they could stay online
    let mut arguments = RelativeArgument::default();
    arguments.set(RelativeArgument::X);
    arguments.set(RelativeArgument::Y);
    arguments.set(RelativeArgument::Z);
    arguments.set(RelativeArgument::X_ROT);
    arguments.set(RelativeArgument::Y_ROT);
    engine
        .send_packet(PlayerPosition {
            x: 0.0,
            y: 0.0,
            z: 0.0,
            y_rot: 0.0,
            x_rot: 0.0,
            relative_arguments: arguments,
            id: VarInt::from(1),
            dismount_vehicle: false,
        })
        .await?;

    client
        .emit_server_message(ClientAction::RemoveClient(client.profile.id))
        .await?;

    Ok(())
}
