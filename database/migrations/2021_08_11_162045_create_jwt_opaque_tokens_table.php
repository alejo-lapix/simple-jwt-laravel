<?php

declare(strict_types=1);

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
        Schema::create('jwt_opaque_tokens', function (Blueprint $table) {
            $table->string('token', 57)->index();
            $table->string('owner_id', 11)->index();
            $table->dateTime('expires_at');
            $table->json('additional')->nullable();

            $table->index(['token', 'owner_id', 'expires_at']);
            $table->primary(['token']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('jwt_opaque_tokens');
    }
};
