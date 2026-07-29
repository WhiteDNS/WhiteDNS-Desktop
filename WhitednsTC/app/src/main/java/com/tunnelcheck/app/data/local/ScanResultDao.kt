package com.tunnelcheck.app.data.local

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface ScanResultDao {
    @Query("SELECT * FROM scan_results ORDER BY scannedAt DESC")
    fun observeAll(): Flow<List<ScanResultEntity>>

    @Query("SELECT * FROM scan_results WHERE classification = :classification ORDER BY scannedAt DESC")
    fun observeByClassification(classification: String): Flow<List<ScanResultEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(result: ScanResultEntity): Long

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAll(results: List<ScanResultEntity>)

    @Query("DELETE FROM scan_results")
    suspend fun clear()
}
