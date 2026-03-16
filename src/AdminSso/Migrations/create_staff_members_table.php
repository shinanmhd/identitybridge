<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('staff_members', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->string('ib_identity_id')->unique()->comment('Identity Bridge admin UUID');
            $table->string('name');
            $table->string('email');
            $table->string('client_app_id')->nullable()->comment('The app this record belongs to');
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('staff_members');
    }
};
