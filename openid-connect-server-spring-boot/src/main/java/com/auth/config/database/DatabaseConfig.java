package com.auth.config.database;

import org.eclipse.persistence.jpa.PersistenceProvider;
import org.eclipse.persistence.platform.database.PostgreSQLPlatform;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.vendor.AbstractJpaVendorAdapter;
import org.springframework.orm.jpa.vendor.Database;
import org.springframework.orm.jpa.vendor.EclipseLinkJpaVendorAdapter;
import org.springframework.transaction.TransactionManager;
import javax.sql.DataSource;
import java.util.HashMap;
import java.util.Map;

@Configuration
public class DatabaseConfig {

    private final DataSource dataSource;

    @Autowired
    public DatabaseConfig(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Bean
    public LocalContainerEntityManagerFactoryBean entityManagerFactory() {
        LocalContainerEntityManagerFactoryBean localContainerEntityManagerFactoryBean = new LocalContainerEntityManagerFactoryBean();
        localContainerEntityManagerFactoryBean.setPackagesToScan("org.mitre");
        localContainerEntityManagerFactoryBean.setPersistenceProviderClass(PersistenceProvider.class);
        localContainerEntityManagerFactoryBean.setDataSource(this.dataSource);
        localContainerEntityManagerFactoryBean.setJpaVendorAdapter(jpaAdapter());
        localContainerEntityManagerFactoryBean.setJpaPropertyMap(jpaPropertyMap());
        localContainerEntityManagerFactoryBean.setPersistenceUnitName("defaultPersistenceUnit");
        return localContainerEntityManagerFactoryBean;
    }

    @Bean
    public AbstractJpaVendorAdapter jpaAdapter() {
        EclipseLinkJpaVendorAdapter eclipseLinkJpaVendorAdapter = new EclipseLinkJpaVendorAdapter();
        eclipseLinkJpaVendorAdapter.setDatabase(Database.POSTGRESQL);
        eclipseLinkJpaVendorAdapter.setDatabasePlatform(PostgreSQLPlatform.class.getName());
        eclipseLinkJpaVendorAdapter.setShowSql(true);
        return eclipseLinkJpaVendorAdapter;
    }

    @Primary
    @Bean(name="defaultTransactionManager")
    public TransactionManager transactionManager(){
        JpaTransactionManager jpaTransactionManager = new JpaTransactionManager();
        jpaTransactionManager.setEntityManagerFactory(entityManagerFactory().getObject());
        return  jpaTransactionManager;
    }

    private Map<String, String> jpaPropertyMap() {
        Map<String, String> jpaPropertyMap = new HashMap<>();
        jpaPropertyMap.put("eclipselink.weaving", "false");
        jpaPropertyMap.put("eclipselink.logging.level", "INFO");
        jpaPropertyMap.put("eclipselink.logging.level.sql", "INFO");
        jpaPropertyMap.put("eclipselink.cache.shared.default", "false");
        return jpaPropertyMap;
    }
}
