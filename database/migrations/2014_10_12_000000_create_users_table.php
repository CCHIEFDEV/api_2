<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('users', function (Blueprint $table) {
            $table->id();
            $table->string('first_name');
            $table->string('last_name');
            $table->string('cover')->nullable();
            $table->string('email')->unique();
            $table->string('password');
            $table->string('country_code');
            $table->string('mobile');
            $table->tinyInteger('type')->default(1);
            $table->text('extra_field')->nullable();
            $table->tinyInteger('status')->default(1);
            $table->text('roles')->nullable();
            $table->rememberToken();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('users');
    }
};
