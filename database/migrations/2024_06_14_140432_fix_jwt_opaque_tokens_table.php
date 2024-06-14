<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class () extends Migration {
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::table('jwt_opaque_tokens', function (Blueprint $table) {
            $table->unsignedBigInteger('id')
                ->nullable(false)
                ->change();

            $table->dropColumn(['created_at', 'updated_at']);

            $table->string('token', 57)
                ->nullable(false)
                ->change();

            $table->string('owner_id', 11)
                ->nullable(false)
                ->change();
        });

        Schema::table('jwt_opaque_tokens', function (Blueprint $table) {
            $table->dropPrimary('id');
            $table->primary('token');
        });

        Schema::table('jwt_opaque_tokens', function (Blueprint $table) {
            $table->dropColumn('id');
            $table->index([
                'token',
                'owner_id',
                'expires_at',
            ]);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('jwt_opaque_tokens', function (Blueprint $table) {
            $table->unsignedBigInteger('id')
                ->nullable(true);

            $table->timestamps();

            $table->string('token', 255)
                ->nullable(false)
                ->change();

            $table->string('owner_id', 255)
                ->nullable(false)
                ->change();

            $table->dropIndex(['token', 'owner_id', 'expires_at']);
        });

        Schema::table('jwt_opaque_tokens', function (Blueprint $table) {
            $table->dropPrimary('token');
            $table->primary('id');
        });

        Schema::table('jwt_opaque_tokens', function (Blueprint $table) {
            $table->unsignedBigInteger('id')
                ->nullable(false)
                ->autoIncrement()
                ->change();
        });
    }
};
