use sqlite::Value;

#[cfg(test)]
use mithril_common::StdResult;
#[cfg(test)]
use mithril_common::entities::Epoch;
use mithril_persistence::sqlite::{Query, SourceAlias, SqLiteEntity, WhereCondition};

use crate::database::record::CertificateRecord;

/// Simple queries to retrieve [CertificateRecord] from the sqlite database.
pub struct GetCertificateRecordQuery {
    condition: WhereCondition,
}

impl GetCertificateRecordQuery {
    pub fn all() -> Self {
        Self {
            condition: WhereCondition::default(),
        }
    }

    pub fn all_genesis() -> Self {
        Self {
            condition: WhereCondition::new("parent_certificate_id is null", vec![]),
        }
    }

    pub fn by_certificate_id(certificate_id: &str) -> Self {
        Self {
            condition: WhereCondition::new(
                "certificate_id = ?*",
                vec![Value::String(certificate_id.to_owned())],
            ),
        }
    }

    #[cfg(test)]
    pub fn by_epoch(epoch: Epoch) -> StdResult<Self> {
        Ok(Self {
            condition: WhereCondition::new("epoch = ?*", vec![Value::Integer(epoch.try_into()?)]),
        })
    }
}

impl Query for GetCertificateRecordQuery {
    type Entity = CertificateRecord;

    fn filters(&self) -> WhereCondition {
        self.condition.clone()
    }

    fn get_definition(&self, condition: &str) -> String {
        let aliases = SourceAlias::new(&[("{:certificate:}", "c")]);
        let projection = Self::Entity::get_projection().expand(aliases);
        format!("select {projection} from certificate as c where {condition} order by ROWID desc")
    }
}

#[cfg(test)]
mod tests {
    use mithril_common::crypto_helper::ProtocolParameters;
    use mithril_common::test::builder::CertificateChainBuilder;
    use mithril_common::test::crypto_helper::setup_certificate_chain;

    use mithril_persistence::sqlite::ConnectionExtensions;

    use crate::database::test_helper::{insert_certificate_records, main_db_connection};

    use super::*;

    #[test]
    fn test_get_certificate_records_by_epoch() {
        let certificates = setup_certificate_chain(5, 2);

        let connection = main_db_connection().unwrap();
        insert_certificate_records(&connection, certificates.certificates_chained.clone());

        let certificate_records: Vec<CertificateRecord> = connection
            .fetch_collect(GetCertificateRecordQuery::by_epoch(Epoch(1)).unwrap())
            .unwrap();
        let expected_certificate_records: Vec<CertificateRecord> = certificates
            .reversed_chain()
            .into_iter()
            .filter_map(|c| (c.epoch == Epoch(1)).then_some(c.to_owned().try_into().unwrap()))
            .collect();
        assert_eq!(expected_certificate_records, certificate_records);

        let certificate_records: Vec<CertificateRecord> = connection
            .fetch_collect(GetCertificateRecordQuery::by_epoch(Epoch(3)).unwrap())
            .unwrap();
        let expected_certificate_records: Vec<CertificateRecord> = certificates
            .reversed_chain()
            .into_iter()
            .filter_map(|c| (c.epoch == Epoch(3)).then_some(c.to_owned().try_into().unwrap()))
            .collect();
        assert_eq!(expected_certificate_records, certificate_records);

        let cursor = connection
            .fetch(GetCertificateRecordQuery::by_epoch(Epoch(5)).unwrap())
            .unwrap();
        assert_eq!(0, cursor.count());
    }

    #[test]
    fn test_get_all_certificate_records() {
        let certificates = setup_certificate_chain(5, 2);
        let expected_certificate_records: Vec<CertificateRecord> = certificates
            .reversed_chain()
            .into_iter()
            .map(|c| c.try_into().unwrap())
            .collect();

        let connection = main_db_connection().unwrap();
        insert_certificate_records(&connection, certificates.certificates_chained.clone());

        let certificate_records: Vec<CertificateRecord> =
            connection.fetch_collect(GetCertificateRecordQuery::all()).unwrap();
        assert_eq!(expected_certificate_records, certificate_records);
    }

    #[test]
    fn test_get_all_genesis_certificate_records() {
        // Two chains with different protocol parameters so generated certificates are different.
        let first_certificates_chain = CertificateChainBuilder::new()
            .with_total_certificates(2)
            .with_protocol_parameters(ProtocolParameters {
                m: 90,
                k: 4,
                phi_f: 0.65,
            })
            .build();
        let first_chain_genesis: CertificateRecord = first_certificates_chain
            .genesis_certificate()
            .clone()
            .try_into()
            .unwrap();
        let second_certificates_chain = CertificateChainBuilder::new()
            .with_total_certificates(2)
            .with_protocol_parameters(ProtocolParameters {
                m: 100,
                k: 5,
                phi_f: 0.65,
            })
            .build();
        let second_chain_genesis: CertificateRecord = second_certificates_chain
            .genesis_certificate()
            .clone()
            .try_into()
            .unwrap();
        assert_ne!(first_chain_genesis, second_chain_genesis);

        let connection = main_db_connection().unwrap();
        let certificate_records: Vec<CertificateRecord> = connection
            .fetch_collect(GetCertificateRecordQuery::all_genesis())
            .unwrap();
        assert_eq!(Vec::<CertificateRecord>::new(), certificate_records);

        insert_certificate_records(&connection, first_certificates_chain.certificates_chained);

        let certificate_records: Vec<CertificateRecord> = connection
            .fetch_collect(GetCertificateRecordQuery::all_genesis())
            .unwrap();
        assert_eq!(vec![first_chain_genesis.to_owned()], certificate_records);

        insert_certificate_records(&connection, second_certificates_chain.certificates_chained);

        let certificate_records: Vec<CertificateRecord> = connection
            .fetch_collect(GetCertificateRecordQuery::all_genesis())
            .unwrap();
        assert_eq!(
            vec![second_chain_genesis, first_chain_genesis],
            certificate_records
        );
    }
}
