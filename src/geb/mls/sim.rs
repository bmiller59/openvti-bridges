//! Test doubles: a second in-process OpenMLS client that plays a Geb member,
//! and an in-memory dyad. This is the bridge's own reading of the guide and
//! answers, written independently of `client.rs`; agreement between the two
//! shows self-consistency, NOT byte-compatibility with real Geb.

#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use super::identity::{SUITE, leaf_capabilities};
use crate::Result;
use crate::geb::codec::GuideCodec;
use crate::geb::crypto::rendezvous::RelayKeys;
use crate::geb::crypto::{b64_encode, did_peer, leaf, pair, sign};
use crate::geb::room::KIND_MAILBOX;
use crate::geb::settle::commit_hash;
use crate::geb::traits::{GebCodec, GebDyad, GebRelay, RelayEvent};
use crate::geb::wire::{Envelope, Frame, GroupOp, LineBody, RoomInfo, signing_doc};
use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use tls_codec::{Deserialize as _, Serialize as _};

/// In-memory dyads between named parties.
#[derive(Default)]
pub struct Bus {
    q: Mutex<HashMap<(String, String), VecDeque<Frame>>>,
}

impl Bus {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    pub fn take(&self, from: &str, to: &str) -> Vec<Frame> {
        self.q
            .lock()
            .map(|mut q| {
                q.remove(&(from.to_string(), to.to_string()))
                    .map(Vec::from)
                    .unwrap_or_default()
            })
            .unwrap_or_default()
    }
    pub fn put(&self, from: &str, to: &str, f: Frame) {
        if let Ok(mut q) = self.q.lock() {
            q.entry((from.to_string(), to.to_string()))
                .or_default()
                .push_back(f);
        }
    }
}

/// A `GebDyad` for one party over a [`Bus`]. Records every frame it sends.
pub struct MemDyad {
    me: String,
    bus: Arc<Bus>,
    pub sent: Mutex<Vec<(String, Frame)>>,
}

impl MemDyad {
    pub fn new(me: &str, bus: &Arc<Bus>) -> Arc<Self> {
        Arc::new(Self {
            me: me.into(),
            bus: bus.clone(),
            sent: Mutex::new(Vec::new()),
        })
    }
}

#[async_trait]
impl GebDyad for MemDyad {
    async fn send(&self, peer_did: &str, frame: &Frame) -> Result<()> {
        frame.validate()?;
        if let Ok(mut s) = self.sent.lock() {
            s.push((peer_did.to_string(), frame.clone()));
        }
        self.bus.put(&self.me, peer_did, frame.clone());
        Ok(())
    }
    async fn recv(&self, peer_did: &str) -> Result<Vec<Frame>> {
        Ok(self.bus.take(peer_did, &self.me))
    }
}

/// A Geb member, written straight from the guide.
pub struct Sim {
    pub did: String,
    pub dev: SigningKey,
    pub provider: OpenMlsRustCrypto,
    pub signer: SignatureKeyPair,
    pub cred: CredentialWithKey,
    pub group: Option<MlsGroup>,
    /// Make this member's KeyPackage binding wrong (the key signs for another).
    pub forge_binding: bool,
    /// Make this member's KeyPackage declare no capabilities beyond default.
    pub plain_capabilities: bool,
    /// Found the group with the mixed wire-format policy, so this member's
    /// commits go out as PublicMessage (which Geb never sends and refuses).
    pub plaintext_handshake: bool,
    /// Make this member's leaf carry no binding at all (a bare `unbound` leaf).
    pub unbound: bool,
}

impl Sim {
    pub fn new(seed: u8) -> Self {
        let dev = SigningKey::from_bytes(&[seed; 32]);
        let did = did_peer::encode(&dev.verifying_key().to_bytes(), &[seed; 32], None).unwrap();
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(SUITE.signature_algorithm()).unwrap();
        signer.store(provider.storage()).unwrap();
        let cred = CredentialWithKey {
            credential: Credential::new(CredentialType::Basic, did.as_bytes().to_vec()),
            signature_key: signer.public().into(),
        };
        Self {
            did,
            dev,
            provider,
            signer,
            cred,
            group: None,
            forge_binding: false,
            plain_capabilities: false,
            plaintext_handshake: false,
            unbound: false,
        }
    }

    pub fn binding_ext(&self) -> Extensions<LeafNode> {
        let leaf_key = <[u8; 32]>::try_from(self.signer.public()).unwrap();
        let b = if self.forge_binding {
            // Signed by a different device key.
            leaf::binding(&SigningKey::from_bytes(&[0xEE; 32]), &self.did, &leaf_key).unwrap()
        } else {
            leaf::binding(&self.dev, &self.did, &leaf_key).unwrap()
        };
        Extensions::single(Extension::Unknown(
            leaf::EXT_LEAF_BINDING,
            UnknownExtension(leaf::extension_value(&b)),
        ))
        .unwrap()
    }

    /// This member's KeyPackage, with the binding and declared extensions.
    pub fn key_package(&self) -> KeyPackage {
        let mut b = KeyPackage::builder();
        if !self.plain_capabilities {
            b = b.leaf_node_capabilities(leaf_capabilities());
            if !self.unbound {
                b = b.leaf_node_extensions(self.binding_ext());
            }
        }
        b.build(SUITE, &self.provider, &self.signer, self.cred.clone())
            .unwrap()
            .key_package()
            .clone()
    }

    /// Found a room the way answer 7 says: `0xF001` policy plus
    /// RequiredCapabilities{extension_types:[0xF001]}.
    pub fn create_room(&mut self, room_id: &str, policy_json: &str) {
        let exts = Extensions::<GroupContext>::from_vec(vec![
            Extension::Unknown(
                leaf::EXT_POLICY,
                UnknownExtension(policy_json.as_bytes().to_vec()),
            ),
            Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
                &[ExtensionType::Unknown(leaf::EXT_POLICY)],
                &[],
                &[],
            )),
        ])
        .unwrap();
        let policy = if self.plaintext_handshake {
            MIXED_PLAINTEXT_WIRE_FORMAT_POLICY
        } else {
            PURE_CIPHERTEXT_WIRE_FORMAT_POLICY
        };
        let leaf_exts = if self.unbound {
            Extensions::empty()
        } else {
            self.binding_ext()
        };
        let cfg = MlsGroupCreateConfig::builder()
            .ciphersuite(SUITE)
            .wire_format_policy(policy)
            .use_ratchet_tree_extension(true)
            .with_group_context_extensions(exts)
            .capabilities(leaf_capabilities())
            .with_leaf_node_extensions(leaf_exts)
            .unwrap()
            .build();
        self.group = Some(
            MlsGroup::new_with_group_id(
                &self.provider,
                &self.signer,
                &cfg,
                GroupId::from_slice(room_id.as_bytes()),
                self.cred.clone(),
            )
            .unwrap(),
        );
    }

    pub fn epoch(&self) -> u64 {
        self.group.as_ref().unwrap().epoch().as_u64()
    }

    /// Stage an Add commit (not merged). Returns (commit, welcome).
    pub fn stage_add(&mut self, kp: KeyPackage) -> (Vec<u8>, Vec<u8>) {
        let (p, s) = (&self.provider, &self.signer);
        let (c, w, _) = self
            .group
            .as_mut()
            .unwrap()
            .add_members(p, s, &[kp])
            .unwrap();
        (
            c.tls_serialize_detached().unwrap(),
            w.tls_serialize_detached().unwrap(),
        )
    }

    pub fn stage_self_update(&mut self) -> Vec<u8> {
        let (p, s) = (&self.provider, &self.signer);
        let b = self
            .group
            .as_mut()
            .unwrap()
            .self_update(p, s, LeafNodeParameters::default())
            .unwrap();
        b.into_commit().tls_serialize_detached().unwrap()
    }

    /// A path-only self-update that replaces this member's leaf parameters
    /// (credential, extensions): the shape of a `heal` when `params` carry the
    /// binding, a `leafAuth` violation when they carry another DID.
    pub fn stage_update_with(&mut self, params: LeafNodeParameters) -> Vec<u8> {
        let (p, s) = (&self.provider, &self.signer);
        let b = self
            .group
            .as_mut()
            .unwrap()
            .self_update(p, s, params)
            .unwrap();
        b.into_commit().tls_serialize_detached().unwrap()
    }

    /// A standalone Proposal (Add), the bytes Geb would refuse. Returns
    /// (proposal message, a commit by reference to it).
    pub fn stage_by_ref_add(&mut self, kp: KeyPackage) -> (Vec<u8>, Vec<u8>) {
        let (p, s) = (&self.provider, &self.signer);
        let g = self.group.as_mut().unwrap();
        g.clear_pending_proposals(p.storage()).unwrap();
        let (prop, _) = g.propose_add_member(p, s, &kp).unwrap();
        let (c, _, _) = g.commit_to_pending_proposals(p, s).unwrap();
        (
            prop.tls_serialize_detached().unwrap(),
            c.tls_serialize_detached().unwrap(),
        )
    }

    /// A standalone Proposal (Add), alone, not committed.
    pub fn stage_proposal(&mut self, kp: KeyPackage) -> Vec<u8> {
        let (p, s) = (&self.provider, &self.signer);
        let g = self.group.as_mut().unwrap();
        g.clear_pending_proposals(p.storage()).unwrap();
        let (prop, _) = g.propose_add_member(p, s, &kp).unwrap();
        prop.tls_serialize_detached().unwrap()
    }

    /// One commit that removes the leaf of `did` and adds `kp`, both inline
    /// (the shape of a re-seat).
    pub fn stage_reseat(&mut self, did: &str, kp: KeyPackage) -> Vec<u8> {
        let idx = self
            .group
            .as_ref()
            .unwrap()
            .members()
            .find(|m| m.credential.serialized_content() == did.as_bytes())
            .unwrap()
            .index;
        let (p, s) = (&self.provider, &self.signer);
        let g = self.group.as_mut().unwrap();
        let b = g
            .commit_builder()
            .propose_removals([idx])
            .propose_adds([kp])
            .load_psks(p.storage())
            .unwrap()
            .build(p.rand(), p.crypto(), s, |_| true)
            .unwrap()
            .stage_commit(p)
            .unwrap();
        b.into_commit().tls_serialize_detached().unwrap()
    }

    /// As [`Sim::stage_reseat`], also returning the Welcome for the re-added
    /// member: (commit, welcome).
    pub fn stage_reseat_full(&mut self, did: &str, kp: KeyPackage) -> (Vec<u8>, Vec<u8>) {
        let idx = self
            .group
            .as_ref()
            .unwrap()
            .members()
            .find(|m| m.credential.serialized_content() == did.as_bytes())
            .unwrap()
            .index;
        let (p, s) = (&self.provider, &self.signer);
        let g = self.group.as_mut().unwrap();
        let b = g
            .commit_builder()
            .propose_removals([idx])
            .propose_adds([kp])
            .load_psks(p.storage())
            .unwrap()
            .build(p.rand(), p.crypto(), s, |_| true)
            .unwrap()
            .stage_commit(p)
            .unwrap();
        let (c, w, _) = b.into_contents();
        (
            c.tls_serialize_detached().unwrap(),
            MlsMessageOut::from_welcome(w.unwrap(), ProtocolVersion::Mls10)
                .tls_serialize_detached()
                .unwrap(),
        )
    }

    /// The first 16 hex of this member's epoch authenticator.
    pub fn auth16(&self) -> String {
        hex::encode(
            self.group
                .as_ref()
                .unwrap()
                .epoch_authenticator()
                .as_slice(),
        )[..16]
            .into()
    }

    /// A signed re-post line `{t:"l", at, text, fk:1, id}`.
    pub fn seal_repost(&mut self, room: &str, at: u64, text: &str, id: &str) -> Vec<u8> {
        let mut line = LineBody::new(at, text.into());
        line.fk = Some(serde_json::json!(1));
        line.id = Some(id.into());
        let doc = signing_doc(room, &self.did, &line).unwrap();
        line.sg = Some(sign::sign_json(&self.dev, &doc).unwrap());
        let pt = GuideCodec.encode_line(&line).unwrap();
        let (p, s) = (&self.provider, &self.signer);
        self.group
            .as_mut()
            .unwrap()
            .create_message(p, s, &pt)
            .unwrap()
            .tls_serialize_detached()
            .unwrap()
    }

    pub fn stage_remove(&mut self, did: &str) -> Vec<u8> {
        let idx = self
            .group
            .as_ref()
            .unwrap()
            .members()
            .find(|m| m.credential.serialized_content() == did.as_bytes())
            .unwrap()
            .index;
        let (p, s) = (&self.provider, &self.signer);
        let (c, _, _) = self
            .group
            .as_mut()
            .unwrap()
            .remove_members(p, s, &[idx])
            .unwrap();
        c.tls_serialize_detached().unwrap()
    }

    /// Stage a policy change (a GroupContextExtensions commit).
    pub fn stage_policy(&mut self, policy_json: &str) -> Vec<u8> {
        let exts = Extensions::<GroupContext>::from_vec(vec![
            Extension::Unknown(
                leaf::EXT_POLICY,
                UnknownExtension(policy_json.as_bytes().to_vec()),
            ),
            Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
                &[ExtensionType::Unknown(leaf::EXT_POLICY)],
                &[],
                &[],
            )),
        ])
        .unwrap();
        let (p, s) = (&self.provider, &self.signer);
        let (c, _, _) = self
            .group
            .as_mut()
            .unwrap()
            .update_group_context_extensions(p, exts, s)
            .unwrap();
        c.tls_serialize_detached().unwrap()
    }

    /// A GroupContextExtensions commit that changes something other than the
    /// policy: the room policy with the required capabilities extension dropped. Not a shape Geb's
    /// `validCommit` is described for.
    pub fn stage_policy_with_extra_extension(&mut self, policy_json: &str) -> Vec<u8> {
        let exts = Extensions::<GroupContext>::from_vec(vec![
            Extension::Unknown(
                leaf::EXT_POLICY,
                UnknownExtension(policy_json.as_bytes().to_vec()),
            ),
            Extension::ExternalSenders(vec![]),
            Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
                &[ExtensionType::Unknown(leaf::EXT_POLICY)],
                &[],
                &[],
            )),
        ])
        .unwrap();
        let (p, s) = (&self.provider, &self.signer);
        let (c, _, _) = self
            .group
            .as_mut()
            .unwrap()
            .update_group_context_extensions(p, exts, s)
            .unwrap();
        c.tls_serialize_detached().unwrap()
    }

    pub fn merge_pending(&mut self) {
        let p = &self.provider;
        self.group
            .as_mut()
            .unwrap()
            .merge_pending_commit(p)
            .unwrap();
    }

    pub fn drop_pending(&mut self) {
        let p = &self.provider;
        self.group
            .as_mut()
            .unwrap()
            .clear_pending_commit(p.storage())
            .unwrap();
    }

    /// Process and merge a commit from someone else (no policy check here).
    pub fn apply(&mut self, commit: &[u8]) -> std::result::Result<(), String> {
        let m = MlsMessageIn::tls_deserialize_exact(commit).map_err(|e| format!("{e:?}"))?;
        let pm = m
            .try_into_protocol_message()
            .map_err(|e| format!("{e:?}"))?;
        let p = &self.provider;
        let g = self.group.as_mut().unwrap();
        let processed = g.process_message(p, pm).map_err(|e| format!("{e:?}"))?;
        match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(s) => {
                g.merge_staged_commit(p, *s).map_err(|e| format!("{e:?}"))
            }
            _ => Err("not a commit".into()),
        }
    }

    /// Geb's rule for a member holding `own` (staged) and having read
    /// `others`: walk ascending SHA-256, skip what `is_valid` rejects, merge
    /// the first that passes. Returns the winning bytes.
    pub fn settle(
        &mut self,
        own: Option<&[u8]>,
        others: &[Vec<u8>],
        is_valid: &dyn Fn(&[u8]) -> bool,
    ) -> Option<Vec<u8>> {
        let mut all: Vec<Vec<u8>> = others.to_vec();
        if let Some(o) = own {
            all.push(o.to_vec());
        }
        all.sort_by_key(|b| commit_hash(b));
        for c in all {
            if !is_valid(&c) {
                continue;
            }
            if Some(c.as_slice()) == own {
                self.merge_pending();
            } else {
                if own.is_some() {
                    self.drop_pending();
                }
                self.apply(&c).unwrap();
            }
            return Some(c);
        }
        if own.is_some() {
            self.drop_pending();
        }
        None
    }

    /// Join from a Welcome frame's bytes.
    pub fn join(&mut self, welcome: &[u8]) {
        let m = MlsMessageIn::tls_deserialize_exact(welcome).unwrap();
        let MlsMessageBodyIn::Welcome(w) = m.extract() else {
            panic!("not a welcome")
        };
        let cfg = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let staged = StagedWelcome::new_from_welcome(&self.provider, &cfg, w, None).unwrap();
        self.group = Some(staged.into_group(&self.provider).unwrap());
    }

    /// The relay keys of this member's current epoch (independent derivation).
    pub fn keys(&self, room: &str) -> RelayKeys {
        let g = self.group.as_ref().unwrap();
        let x = |l: &str| -> [u8; 32] {
            g.export_secret(self.provider.crypto(), l, room.as_bytes(), 32)
                .unwrap()
                .try_into()
                .unwrap()
        };
        RelayKeys::from_parts(x("geb/room/v2/nostr"), x("geb/room/v2/aead"))
    }

    /// A signed line sealed as an application message.
    pub fn seal_line(&mut self, room: &str, at: u64, text: &str, sign_it: bool) -> Vec<u8> {
        let mut line = LineBody::new(at, text.into());
        if sign_it {
            let doc = signing_doc(room, &self.did, &line).unwrap();
            line.sg = Some(sign::sign_json(&self.dev, &doc).unwrap());
        }
        let pt = GuideCodec.encode_line(&line).unwrap();
        let (p, s) = (&self.provider, &self.signer);
        self.group
            .as_mut()
            .unwrap()
            .create_message(p, s, &pt)
            .unwrap()
            .tls_serialize_detached()
            .unwrap()
    }

    /// Open an application message: (sender DID, line).
    pub fn open_line(&mut self, bytes: &[u8]) -> Option<(String, LineBody)> {
        let m = MlsMessageIn::tls_deserialize_exact(bytes).ok()?;
        let pm = m.try_into_protocol_message().ok()?;
        let p = &self.provider;
        let g = self.group.as_mut().unwrap();
        let processed = g.process_message(p, pm).ok()?;
        let sender =
            String::from_utf8(processed.credential().serialized_content().to_vec()).ok()?;
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(a) => {
                Some((sender, GuideCodec.decode_line(&a.into_bytes()).ok()?))
            }
            _ => None,
        }
    }
}

/// The welcome frame as Geb sends it (answer 8).
pub fn welcome_frame(room_id: &str, founder: &str, policy_json: &str, welcome: &[u8]) -> Frame {
    Frame::Group(GroupOp::Welcome {
        room: RoomInfo {
            v: 2,
            id: room_id.into(),
            name: "Test room".into(),
            founder: founder.into(),
            since: 1_700_000_000_000,
            policy: policy_json.into(),
            name_at: None,
            name_by: None,
            extra: Default::default(),
        },
        w: b64_encode(welcome),
        ent: None,
    })
}

/// Post an envelope to the relay under `keys`.
pub async fn post(relay: &Arc<dyn GebRelay>, keys: &RelayKeys, env: &Envelope, created_at: u64) {
    let bytes = GuideCodec.encode_envelope(env).unwrap();
    let content = pair::seal(keys, KIND_MAILBOX, &bytes).unwrap();
    let ev = RelayEvent::sign(
        &keys.nostr_secret,
        KIND_MAILBOX,
        created_at,
        crate::geb::event::standard_tags(created_at),
        content,
    )
    .unwrap();
    relay.publish(ev).await.unwrap();
}

pub fn ml(bytes: &[u8]) -> Envelope {
    Envelope::Ml {
        m: b64_encode(bytes),
    }
}

pub fn mc(e: u64, bytes: &[u8]) -> Envelope {
    Envelope::Mc {
        e,
        m: b64_encode(bytes),
    }
}
