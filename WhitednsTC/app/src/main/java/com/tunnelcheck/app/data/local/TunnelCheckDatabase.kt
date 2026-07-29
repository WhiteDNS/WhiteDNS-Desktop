package com.tunnelcheck.app.data.local

import androidx.room.Database
import androidx.room.migration.Migration
import androidx.room.RoomDatabase
import androidx.sqlite.db.SupportSQLiteDatabase

@Database(entities = [ScanResultEntity::class], version = 2, exportSchema = true)
abstract class TunnelCheckDatabase : RoomDatabase() {
    abstract fun scanResultDao(): ScanResultDao

    companion object {
        val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE scan_results ADD COLUMN scanMode TEXT NOT NULL DEFAULT 'Quick'")
            }
        }
    }
}
