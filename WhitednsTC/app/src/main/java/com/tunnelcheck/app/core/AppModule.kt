package com.tunnelcheck.app.core

import android.content.Context
import androidx.room.Room
import com.tunnelcheck.app.data.local.ScanResultDao
import com.tunnelcheck.app.data.local.TunnelCheckDatabase
import com.tunnelcheck.app.data.repo.DefaultScanRepository
import com.tunnelcheck.app.domain.repo.ScanRepository
import com.tunnelcheck.app.engine.GoEngineBridge
import com.tunnelcheck.app.engine.TunnelEngine
import com.tunnelcheck.app.ui.SettingsStore
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
abstract class BindingsModule {
    @Binds abstract fun bindEngine(bridge: GoEngineBridge): TunnelEngine
    @Binds abstract fun bindRepository(repository: DefaultScanRepository): ScanRepository
}

@Module
@InstallIn(SingletonComponent::class)
object AppModule {
    @Provides
    @Singleton
    fun provideDatabase(@ApplicationContext context: Context): TunnelCheckDatabase =
        Room.databaseBuilder(context, TunnelCheckDatabase::class.java, "tunnelcheck.db")
            .addMigrations(TunnelCheckDatabase.MIGRATION_1_2)
            .build()

    @Provides
    fun provideScanResultDao(database: TunnelCheckDatabase): ScanResultDao = database.scanResultDao()

    @Provides
    @Singleton
    fun provideSettingsStore(@ApplicationContext context: Context): SettingsStore = SettingsStore(context)
}
