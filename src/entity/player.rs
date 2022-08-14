use mc_registry::shared_types::GameProfile;

pub struct EntityPlayer {
    profile: GameProfile,
    entity_id: i32,
}

impl EntityPlayer {
    pub fn new(profile: GameProfile, entity_id: i32) -> Self {
        Self { profile, entity_id }
    }

    pub fn entity_id(&self) -> i32 {
        self.entity_id
    }

    pub fn profile(&self) -> &GameProfile {
        &self.profile
    }

    pub fn profile_mut(&mut self) -> &mut GameProfile {
        &mut self.profile
    }
}
