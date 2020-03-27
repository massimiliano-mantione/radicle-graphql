#![deny(missing_debug_implementations, missing_copy_implementations)]
#![warn(
    clippy::option_unwrap_used,
    clippy::result_unwrap_used,
    clippy::print_stdout,
    clippy::wrong_pub_self_convention,
    clippy::mut_mut,
    clippy::non_ascii_literal,
    clippy::similar_names,
    clippy::unicode_not_nfc,
    clippy::enum_glob_use,
    clippy::if_not_else,
    clippy::items_after_statements,
    clippy::used_underscore_binding,
    clippy::cargo_common_metadata,
    clippy::dbg_macro,
    clippy::doc_markdown,
    clippy::filter_map,
    clippy::map_flatten,
    clippy::match_same_arms,
    clippy::needless_borrow,
    clippy::needless_pass_by_value,
    clippy::option_map_unwrap_or,
    clippy::option_map_unwrap_or_else,
    clippy::redundant_clone,
    clippy::result_map_unwrap_or_else,
    clippy::unnecessary_unwrap,
    clippy::unseparated_literal_suffix,
    clippy::wildcard_dependencies
)]

use diesel::backend::Backend;
use diesel::deserialize::{self, FromSql};
use diesel::r2d2::{ConnectionManager, PooledConnection};
use diesel::serialize::{self, ToSql};
use diesel::sql_types::Text;
use diesel::{AsExpression, Connection, FromSqlRow, Identifiable};
use juniper::LookAheadSelection;
use std::io::Write;
use wundergraph::error::Result;
use wundergraph::query_builder::selection::offset::ApplyOffset;
use wundergraph::query_builder::selection::{BoxedQuery, LoadingHandler, QueryModifier};
use wundergraph::query_builder::types::{HasOne, WundergraphValue};
use wundergraph::scalar::WundergraphScalarValue;
use wundergraph::WundergraphContext;
use wundergraph::WundergraphEntity;

use diesel::table;
use juniper::GraphQLEnum;

use crate::mutations::*;

#[derive(
    Debug, Copy, Clone, AsExpression, FromSqlRow, GraphQLEnum, WundergraphValue, Eq, PartialEq, Hash,
)]
#[sql_type = "Text"]
pub enum KeyAlgo {
    FOO,
    BAR,
}

impl KeyAlgo {
    pub fn from_str(text: &str) -> Option<Self> {
        match text {
            "FOO" => Some(KeyAlgo::FOO),
            "BAR" => Some(KeyAlgo::BAR),
            _ => None,
        }
    }

    pub fn to_str(&self) -> &'static str {
        match self {
            KeyAlgo::FOO => "FOO",
            KeyAlgo::BAR => "BAR",
        }
    }
}

impl<DB> ToSql<Text, DB> for KeyAlgo
where
    DB: Backend,
    String: ToSql<Text, DB>,
{
    fn to_sql<W: Write>(&self, out: &mut serialize::Output<'_, W, DB>) -> serialize::Result {
        self.to_str().to_owned().to_sql(out)
    }
}

impl<DB> FromSql<Text, DB> for KeyAlgo
where
    DB: Backend,
    String: FromSql<Text, DB>,
{
    fn from_sql(bytes: Option<&DB::RawValue>) -> deserialize::Result<Self> {
        let value = String::from_sql(bytes)?;
        match KeyAlgo::from_str(&value) {
            Some(algo) => Ok(algo),
            None => unreachable!(),
        }
    }
}

#[derive(
    Debug, Copy, Clone, AsExpression, FromSqlRow, GraphQLEnum, WundergraphValue, Eq, PartialEq, Hash,
)]
#[sql_type = "Text"]
pub enum EntityStatus {
    OLD,
    CURRENT,
    DRAFT,
}

impl EntityStatus {
    pub fn from_str(text: &str) -> Option<Self> {
        match text {
            "OLD" => Some(EntityStatus::OLD),
            "CURRENT" => Some(EntityStatus::CURRENT),
            "DRAFT" => Some(EntityStatus::DRAFT),
            _ => None,
        }
    }

    pub fn to_str(&self) -> &'static str {
        match self {
            EntityStatus::OLD => "OLD",
            EntityStatus::CURRENT => "CURRENT",
            EntityStatus::DRAFT => "DRAFT",
        }
    }
}

impl<DB> ToSql<Text, DB> for EntityStatus
where
    DB: Backend,
    String: ToSql<Text, DB>,
{
    fn to_sql<W: Write>(&self, out: &mut serialize::Output<'_, W, DB>) -> serialize::Result {
        self.to_str().to_owned().to_sql(out)
    }
}

impl<DB> FromSql<Text, DB> for EntityStatus
where
    DB: Backend,
    String: FromSql<Text, DB>,
{
    fn from_sql(bytes: Option<&DB::RawValue>) -> deserialize::Result<Self> {
        let value = String::from_sql(bytes)?;
        match EntityStatus::from_str(&value) {
            Some(status) => Ok(status),
            None => unreachable!(),
        }
    }
}

table! {
    entities(hash) {
        hash -> Text,
        parent -> Text,
        revision -> Integer,
        timestamp -> Timestamp,
        status -> Text,
        name -> Text,
        info -> Nullable<Text>,
    }
}

table! {
    keys {
        id -> Integer,
        data -> Text,
        algo -> Text,
    }
}

table! {
    devices(key) {
        key -> Integer,
        address -> Nullable<Text>,
    }
}

table! {
    signatures(key, hash) {
        key -> Integer,
        hash -> Text,
        data -> Text,
        by -> Nullable<Text>,
    }
}

table! {
    certifiers(certifier, entity) {
        certifier -> Text,
        entity -> Text,
    }
}

#[derive(Clone, Debug, Queryable, Eq, PartialEq, Hash, WundergraphEntity, Identifiable)]
#[table_name = "entities"]
#[primary_key(hash)]
pub struct Entity {
    hash: String,
    parent: String,
    revision: i32,
    timestamp: chrono::naive::NaiveDateTime,
    status: EntityStatus,
    name: String,
    info: Option<String>,
    //keys: HasMany<Key, keys::id>,
    //signatures: HasMany<Signature, signatures::key>,
}

#[derive(Clone, Debug, Queryable, Eq, PartialEq, Hash, WundergraphEntity, Identifiable)]
#[table_name = "keys"]
#[primary_key(id)]
pub struct Key {
    id: i32,
    data: String,
    algo: KeyAlgo,
}

#[derive(Clone, Debug, Queryable, Eq, PartialEq, Hash, WundergraphEntity, Identifiable)]
#[table_name = "devices"]
#[primary_key(key)]
pub struct Device {
    key: HasOne<i32, Key>,
    address: Option<String>,
}

#[derive(Clone, Debug, Queryable, Eq, PartialEq, Hash, WundergraphEntity, Identifiable)]
#[table_name = "signatures"]
#[primary_key(key, hash)]
pub struct Signature {
    key: HasOne<i32, Key>,
    hash: HasOne<String, Entity>,
    data: String,
    by: Option<HasOne<String, Entity>>,
}

#[derive(Clone, Debug, Queryable, Eq, PartialEq, Hash, WundergraphEntity, Identifiable)]
#[table_name = "certifiers"]
#[primary_key(certifier, entity)]
pub struct Certifier {
    certifier: HasOne<String, Entity>,
    entity: HasOne<String, Entity>,
}

wundergraph::query_object! {
    /// Global query object for the schema
    Query {
        Entity,
        Key,
        Device,
        Signature,
        Certifier,
    }
}

#[derive(Debug)]
pub struct MyContext<Conn>
where
    Conn: Connection + 'static,
{
    conn: PooledConnection<ConnectionManager<Conn>>,
}

impl<Conn> MyContext<Conn>
where
    Conn: Connection + 'static,
{
    pub fn new(conn: PooledConnection<ConnectionManager<Conn>>) -> Self {
        Self { conn }
    }
}

impl<T, C, DB> QueryModifier<T, DB> for MyContext<C>
where
    C: Connection<Backend = DB>,
    DB: Backend + ApplyOffset + 'static,
    T: LoadingHandler<DB, Self>,
    Self: WundergraphContext,
    Self::Connection: Connection<Backend = DB>,
{
    fn modify_query<'a>(
        &self,
        _select: &LookAheadSelection<'_, WundergraphScalarValue>,
        query: BoxedQuery<'a, T, DB, Self>,
    ) -> Result<BoxedQuery<'a, T, DB, Self>> {
        match T::TYPE_NAME {
            //            "Heros" => Err(Error::from_boxed_compat(String::from("Is user").into())),
            _ => Ok(query),
        }
    }
}

impl WundergraphContext for MyContext<DBConnection> {
    type Connection = diesel::r2d2::PooledConnection<diesel::r2d2::ConnectionManager<DBConnection>>;

    fn get_connection(&self) -> &Self::Connection {
        &self.conn
    }
}

//#[cfg(feature = "postgres")]
//pub type DBConnection = ::diesel::PgConnection;

//#[cfg(feature = "sqlite")]
pub type DBConnection = ::diesel::SqliteConnection;

//pub type DbBackend = <DBConnection as Connection>::Backend;

pub type Schema<Ctx> =
    juniper::RootNode<'static, Query<Ctx>, Mutation<Ctx>, WundergraphScalarValue>;
