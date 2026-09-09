<template>
    <div>
        <div class="row">
            <div class="col-12">
                <card class="xss-card-container">
                    <div class="row pl-4 pr-4 p-2" style="display: block;">
                        <div>
                            <h1><i class="fas fa-file-code"></i> XSS Payloads</h1>
                        </div>
                        <ul class="nav nav-pills nav-pills-secondary mb-3">
                            <li class="nav-item" v-for="category in categories" v-bind:key="category.id">
                                <a class="nav-link" v-bind:class="{active: active_category === category.id}" v-on:click.prevent="active_category = category.id" href="#">{{category.label}}</a>
                            </li>
                        </ul>
                        <card v-for="payload in visible_payloads" v-bind:key="payload.id">
                            <h4 class="card-title" v-html="payload.title"></h4>
                            <h6 class="card-subtitle mb-2 text-muted">{{payload.description}}</h6>
                            <p class="card-text">
                                <base-input type="text" v-bind:value="payload_value(payload)" placeholder="..."></base-input>
                            </p>
                            <base-button type="primary" v-clipboard:copy="payload_value(payload)"><i class="far fa-copy"></i> Copy Payload</base-button>
                            <div class="payload-notes mt-3">
                                <p class="payload-note mb-2"><span class="payload-note-label">Example:</span> <span v-html="payload.example"></span></p>
                                <p class="payload-note mb-2"><span class="payload-note-label">Caveats:</span> <span v-html="payload.caveats"></span></p>
                                <p class="payload-note mb-0"><span class="payload-note-label">When it works:</span> <span v-html="payload.when"></span></p>
                            </div>
                        </card>
                    </div>
                </card>
            </div>
        </div>
    </div>
</template>
<script>
import api_request from '@/libs/api.js';
import payloads_module from '@/libs/payloads.js';

export default {
    data() {
        return {
            categories: payloads_module.categories,
            payloads: payloads_module.payloads,
            active_category: payloads_module.categories[0].id,
            base_domain: '',
        }
    },
    computed: {
        visible_payloads: function() {
            if (this.active_category === 'all') {
                return this.payloads;
            }
            return this.payloads.filter((payload) => payload.category === this.active_category);
        },
    },
    methods: {
        payload_value: function(payload) {
            return payload.func(this.base_domain);
        },
    },
    async mounted() {
        // For debugging
        window.app = this;

        // Base domain
        this.base_domain = api_request.BASE_DOMAIN;
    }
};
</script>
<style>
.control-label {
    color: #d3d3d7 !important;
    display: inline;
}
.payload-note {
    color: #d3d3d7;
    font-size: 0.9rem;
}
.payload-note-label {
    font-weight: bold;
}
</style>
