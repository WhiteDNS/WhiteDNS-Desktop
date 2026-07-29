package com.tunnelcheck.app.worker

import android.content.Context
import androidx.hilt.work.HiltWorker
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.tunnelcheck.app.domain.repo.ScanRepository
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject

@HiltWorker
class ScheduledRetestWorker @AssistedInject constructor(
    @Assisted context: Context,
    @Assisted params: WorkerParameters,
    private val repository: ScanRepository
) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result {
        // Scheduled retests are intentionally explicit: the app must enqueue work only
        // after the user selects endpoints and a schedule in the UI.
        return Result.success()
    }
}
