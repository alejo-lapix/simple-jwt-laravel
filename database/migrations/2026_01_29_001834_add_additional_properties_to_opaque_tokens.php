<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::table('jwt_opaque_tokens', function (Blueprint $table) {
            $table->json('additional')->nullable();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('jwt_opaque_tokens', function (Blueprint $table) {
            $table->dropColumn('additional');
        });
    }
};
